//! Kernel 3: Visa qVSDC (EMV Contactless Book C-3). Mirrors `python/openpaykernel/kernels/visa.py`.

use alloc::vec::Vec;

use crate::apdu::{self, TransmissionError};
use crate::config::bit;
use crate::dol;
use crate::emvproc::{
    check_mandatory, pan_hex, parse_afl, parse_gpo_response, read_application_data, retrieve_icc_pk,
    static_data_to_authenticate, yymmdd_bcd, yymmdd_str, KResult, KernelError, Session,
};
use crate::entry_point::{ContactlessKernel, KernelContext};
use crate::oda::{self, OdaError};
use crate::outcome::{Cvm, L2Error, Message, Outcome, Start, Status};
use crate::tlv;

const DATA_RECORD_TAGS: &[u32] = &[
    0x82, 0x95, 0x9A, 0x9C, 0x5F2A, 0x9F02, 0x9F03, 0x9F10, 0x9F1A, 0x9F26, 0x9F27, 0x9F36, 0x9F37, 0x9F66, 0x9F6C,
    0x9F6E, 0x9F7C, 0x5F34, 0x57, 0x5A, 0x5F24, 0x9F34, 0x9F33, 0x9F35, 0x84, 0x9F06,
];

const AAC: i32 = 0x00;
const TC: i32 = 0x40;
const ARQC: i32 = 0x80;

/// Visa IAD formats 0/1/3: byte 5 bits 6-5 hold the cryptogram type.
fn cid_from_iad(iad: Option<&[u8]>) -> i32 {
    match iad.and_then(|i| i.get(4)).map(|b| (b >> 4) & 3) {
        Some(0) => AAC,
        Some(1) => TC,
        Some(2) => ARQC,
        _ => -1,
    }
}

fn hex_upper(b: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for x in b {
        s.push_str(&alloc::format!("{:02X}", x));
    }
    s
}

fn track2_matches_pan(t2: Option<&[u8]>, pan: Option<&[u8]>) -> bool {
    match (t2, pan) {
        (Some(t2), Some(pan)) => {
            let h = hex_upper(t2);
            h.split('D').next().unwrap_or("") == pan_hex(pan)
        }
        _ => true,
    }
}

fn pan_from_track2(t2: &[u8]) -> Vec<u8> {
    let h = hex_upper(t2);
    let mut p: alloc::string::String = h.split('D').next().unwrap_or("").into();
    if p.len() % 2 == 1 {
        p.push('F');
    }
    (0..p.len() / 2).map(|i| u8::from_str_radix(&p[2 * i..2 * i + 2], 16).unwrap_or(0xFF)).collect()
}

pub struct VisaKernel;

impl ContactlessKernel for VisaKernel {
    fn kernel_id(&self) -> u32 {
        3
    }

    fn start(&self, ctx: &mut KernelContext<'_, '_>) -> Result<Outcome, TransmissionError> {
        start_quick_flow(ctx, &[])
    }
}

/// The qVSDC quick flow, shared with UnionPay qUICS (kernel 7). `extra_record_tags` are added
/// to the data record of a decided transaction (the scheme profile).
pub(crate) fn start_quick_flow(
    ctx: &mut KernelContext<'_, '_>,
    extra_record_tags: &[u32],
) -> Result<Outcome, TransmissionError> {
    let mut s = Session::new(ctx.env, ctx.aid, ctx.txn, ctx.chan);
    let result = run(ctx.fci, &ctx.candidate.adf_name, ctx.pre.ttq.unwrap_or(ctx.aid.ttq), &mut s);
    match result {
        Ok(mut o) => {
            if !o.data_record.is_empty() {
                o.data_record.extend(s.db.subset(extra_record_tags));
            }
            Ok(o)
        }
        Err(KernelError::Transmission) => Err(TransmissionError),
        Err(KernelError::Card(sw)) => Ok(Outcome::end_application(L2Error::CardDataError, sw, None)),
        Err(KernelError::Parse) => Ok(Outcome::end_application(L2Error::ParsingError, 0, None)),
    }
}

fn run(fci_raw: &[u8], adf_name: &[u8], ttq: [u8; 4], s: &mut Session) -> KResult<Outcome> {
    let fci = tlv::parse(fci_raw)?;
    if fci.first().map(|t| t.tag) != Some(0x6F) {
        return Ok(Outcome::select_next(L2Error::ParsingError, 0));
    }
    s.db.store_card_data(&fci)?;
    s.db.set(0x9F06, adf_name);
    s.db.set(0x9F66, &ttq);

    let pdol = match s.get(0x9F38) {
        Some(p) if !p.is_empty() && dol::contains(p, 0x9F66) => p.to_vec(),
        // Without TTQ in the PDOL the card only supports MSD, which is not implemented.
        _ => return Ok(Outcome::end_application(L2Error::CardDataMissing, 0, Some(Message::InsertSwipeOrTryAnother))),
    };
    s.pdol_data = s.build_dol(&pdol)?;
    let r = s.exchange(&apdu::get_processing_options(&s.pdol_data))?;
    match r.sw {
        0x6984 => return Ok(Outcome::try_another_interface()),
        0x6985 => return Ok(Outcome::select_next(L2Error::StatusBytes, r.sw)),
        0x6986 => {
            let mut o = Outcome::new(Status::TryAgain, Cvm::NotApplicable, Some(Message::SeePhone));
            o.start = Start::B;
            o.field_off_request_ms = Some(1300);
            return Ok(o);
        }
        0x9000 => {}
        sw => return Ok(Outcome::end_application(L2Error::StatusBytes, sw, None)),
    }
    if r.data.first() != Some(&0x77) {
        return Ok(Outcome::end_application(L2Error::CardDataError, 0, None)); // format 1 invalid for qVSDC
    }
    parse_gpo_response(&r.data, &mut s.db)?;

    if s.get(0x94).is_some_and(|a| !a.is_empty()) {
        parse_afl(s.get(0x94).unwrap_or(&[]))?;
        read_application_data(s)?;
    }

    let cid = match s.get(0x9F27) {
        Some([]) => return Ok(Outcome::end_application(L2Error::CardDataError, 0, None)),
        Some(c) => (c[0] & 0xC0) as i32,
        None => cid_from_iad(s.get(0x9F10)),
    };
    if cid != AAC && cid != TC && cid != ARQC {
        return Ok(Outcome::end_application(L2Error::CardDataError, 0, None));
    }
    let mut mandatory: Vec<u32> = alloc::vec![0x82, 0x9F36, 0x9F10];
    if cid != AAC {
        mandatory.push(0x9F26);
    }
    if !s.db.has(0x57) && !s.db.has(0x5A) {
        mandatory.push(0x57);
    }
    check_mandatory(s, &mandatory)?;
    if !track2_matches_pan(s.get(0x57), s.get(0x5A)) {
        return Ok(Outcome::end_application(L2Error::CardDataError, 0, None));
    }

    let online_capable = s.env.terminal.online_capable() && !bit(Some(&ttq), 1, 4);
    let ctq: Option<Vec<u8>> = s.get(0x9F6C).filter(|c| !c.is_empty()).map(|c| c.to_vec());
    let ctq = ctq.as_deref();

    let cvm = match cvm(s, &ttq, ctq, cid) {
        Some(c) => c,
        None => return Ok(outcome(s, Status::Declined, Cvm::NoCvm)),
    };
    if cid == AAC {
        return Ok(outcome(s, Status::Declined, cvm));
    }
    if cid == ARQC {
        return Ok(outcome(s, Status::OnlineRequest, cvm));
    }

    // TC: offline approval needs the checks below and fDDA to pass
    if cvm == Cvm::OnlinePin {
        return Ok(outcome(s, if online_capable { Status::OnlineRequest } else { Status::Declined }, cvm));
    }
    let offline_failure = |s: &mut Session| {
        if bit(ctq, 1, 6) && online_capable {
            outcome(s, Status::OnlineRequest, cvm)
        } else if bit(ctq, 1, 5) && bit(Some(&ttq), 1, 5) {
            Outcome::try_another_interface()
        } else {
            outcome(s, Status::Declined, cvm)
        }
    };
    if let Some(exp) = s.get(0x5F24) {
        if yymmdd_bcd(exp)? < yymmdd_str(&s.txn.date) {
            return Ok(offline_failure(s));
        }
    }
    let pan = match s.get(0x5A).filter(|p| !p.is_empty()) {
        Some(p) => Some(p.to_vec()),
        None => s.get(0x57).map(pan_from_track2),
    };
    if let Some(pan) = pan {
        if !pan.is_empty() && s.env.terminal.exception_file.contains(&pan_hex(&pan)) {
            return Ok(offline_failure(s));
        }
    }
    if !bit(s.get(0x82), 1, 6) {
        return Ok(offline_failure(s));
    }
    if fdda(s).is_err() {
        return Ok(offline_failure(s));
    }
    Ok(outcome(s, Status::Approved, cvm))
}

fn fdda(s: &mut Session) -> Result<(), OdaError> {
    let sdad = s.get(0x9F4B).ok_or(OdaError("SDAD missing"))?.to_vec();
    let icc = retrieve_icc_pk(s)?;
    let mut tdd = s.get(0x9F37).unwrap_or(&[]).to_vec();
    if let Some(cad) = s.get(0x9F69).filter(|c| c.first() == Some(&0x01)) {
        let cad = cad.to_vec();
        tdd.extend_from_slice(s.get(0x9F02).unwrap_or(&[]));
        tdd.extend_from_slice(s.get(0x5F2A).unwrap_or(&[]));
        tdd.extend_from_slice(&cad);
    }
    static_data_to_authenticate(s)?;
    let dd = oda::verify_dynamic_signature(&icc, &sdad, &tdd)?;
    s.db.set(0x9F4C, oda::icc_dynamic_number(&dd));
    Ok(())
}

/// Book C-3 5.6. None = no CVM can be performed (decline).
fn cvm(s: &Session, ttq: &[u8; 4], ctq: Option<&[u8]>, cid: i32) -> Option<Cvm> {
    let t = Some(&ttq[..]);
    if !bit(t, 2, 7) {
        return Some(Cvm::NoCvm);
    }
    if let Some(ctq_bytes) = ctq {
        let c = Some(ctq_bytes);
        if bit(c, 1, 8) && bit(t, 1, 3) {
            return Some(Cvm::OnlinePin);
        }
        if bit(c, 2, 8) {
            if let Some(cad) = s.get(0x9F69) {
                if cad.len() >= 7 && cad[5..7] != ctq_bytes[..ctq_bytes.len().min(2)] {
                    return None;
                }
            }
            return Some(Cvm::ConfirmationCodeVerified);
        }
        if bit(c, 1, 7) && bit(t, 1, 2) {
            return Some(Cvm::Signature);
        }
        return None;
    }
    if bit(t, 1, 2) {
        return Some(Cvm::Signature);
    }
    if bit(t, 1, 3) && cid == ARQC {
        return Some(Cvm::OnlinePin);
    }
    None
}

fn outcome(s: &mut Session, status: Status, cvm: Cvm) -> Outcome {
    s.sync();
    let msg = match status {
        Status::Approved if cvm == Cvm::Signature => Message::ApprovedSign,
        Status::Approved => Message::Approved,
        Status::Declined => Message::NotAuthorised,
        _ => Message::Authorising,
    };
    let mut o = Outcome::new(status, cvm, Some(msg));
    o.data_record = s.db.subset(DATA_RECORD_TAGS);
    o
}
