//! Kernel 6: Discover D-PAS (EMV Contactless Book C-6), EMV mode.
//! Mirrors `python/openpaykernel/kernels/discover.py`.
//!
//! TTQ in the PDOL → GPO (AIP, AFL, Card Processing Requirements 9F71) → READ RECORD →
//! interface-switch rules → CDA selection → processing restrictions → CVM from TTQ + CPR →
//! floor limit → TAA → GENERATE AC (CDA) → outcome.
//!
//! CPR bits used: (1,8) online PIN required, (1,7) signature required, (1,3) switch interface
//! for cash, (1,2) switch interface for cashback, (2,8) consumer device CVM performed.
//! Not verified against the official Book C-6 text. Mag-stripe mode is not implemented.

use alloc::vec::Vec;

use crate::apdu::{self, TransmissionError};
use crate::config::bit;
use crate::emvproc::{
    check_mandatory, parse_gpo_response, processing_restrictions, read_application_data, terminal_action_analysis,
    KResult, KernelError, Session, TVR_FLOOR_LIMIT,
};
use crate::entry_point::{ContactlessKernel, KernelContext};
use crate::kernels::common;
use crate::outcome::{Cvm, L2Error, Message, Outcome, Start, Status};

const DATA_RECORD_TAGS: &[u32] = &[
    0x9F02, 0x9F03, 0x9F26, 0x9F27, 0x9F36, 0x9F10, 0x9F37, 0x95, 0x9A, 0x9C, 0x5F2A, 0x82, 0x9F1A, 0x9F33, 0x9F34,
    0x9F35, 0x9F66, 0x9F71, 0x5A, 0x5F34, 0x57, 0x5F24, 0x84, 0x9F06,
];

pub struct DiscoverKernel;

impl ContactlessKernel for DiscoverKernel {
    fn kernel_id(&self) -> u32 {
        6
    }

    fn start(&self, ctx: &mut KernelContext<'_, '_>) -> Result<Outcome, TransmissionError> {
        let ttq = ctx.pre.ttq.unwrap_or(ctx.aid.ttq);
        let mut s = Session::new(ctx.env, ctx.aid, ctx.txn, ctx.chan);
        match run(ctx.fci, &ctx.candidate.adf_name, ttq, &mut s) {
            Ok(o) => Ok(o),
            Err(KernelError::Transmission) => Err(TransmissionError),
            Err(KernelError::Card(sw)) => {
                Ok(Outcome::end_application(L2Error::CardDataError, sw, Some(Message::ProcessingError)))
            }
            Err(KernelError::Parse) => {
                Ok(Outcome::end_application(L2Error::ParsingError, 0, Some(Message::ProcessingError)))
            }
        }
    }
}

fn cvm_results(cvm: Cvm) -> [u8; 3] {
    match cvm {
        Cvm::OnlinePin => [0x42, 0x03, 0x00],
        Cvm::Signature => [0x1E, 0x03, 0x00],
        Cvm::ConfirmationCodeVerified => [0x01, 0x00, 0x02],
        _ => [0x3F, 0x00, 0x00],
    }
}

/// CVM from the TTQ and the CPR. None = no CVM can be performed (decline).
fn cvm_from_cpr(ttq: &[u8; 4], cpr: Option<&[u8]>) -> Option<Cvm> {
    let t = Some(&ttq[..]);
    if !bit(t, 2, 7) {
        return Some(Cvm::NoCvm);
    }
    if cpr.is_some_and(|c| !c.is_empty()) {
        if bit(cpr, 1, 8) && bit(t, 1, 3) {
            return Some(Cvm::OnlinePin);
        }
        if bit(cpr, 2, 8) {
            return Some(Cvm::ConfirmationCodeVerified);
        }
        if bit(cpr, 1, 7) && bit(t, 1, 2) {
            return Some(Cvm::Signature);
        }
        return None;
    }
    if bit(t, 1, 2) {
        return Some(Cvm::Signature);
    }
    if bit(t, 1, 3) {
        return Some(Cvm::OnlinePin);
    }
    None
}

fn run(fci: &[u8], adf_name: &[u8], ttq: [u8; 4], s: &mut Session) -> KResult<Outcome> {
    let cfg = s.aid;
    if !common::store_fci(s, fci, adf_name)? {
        return Ok(Outcome::select_next(L2Error::ParsingError, 0));
    }
    s.db.set(0x9F66, &ttq);

    // GET PROCESSING OPTIONS
    let pdol = s.get(0x9F38).unwrap_or(&[]).to_vec();
    s.pdol_data = s.build_dol(&pdol)?;
    let r = s.exchange(&apdu::get_processing_options(&s.pdol_data))?;
    match r.sw {
        0x6984 => return Ok(Outcome::try_another_interface()),
        0x6986 => {
            let mut o = Outcome::new(Status::TryAgain, Cvm::NotApplicable, Some(Message::SeePhone));
            o.start = Start::B;
            o.field_off_request_ms = Some(1300);
            return Ok(o);
        }
        0x9000 => {}
        sw => return Ok(Outcome::select_next(L2Error::StatusBytes, sw)),
    }
    parse_gpo_response(&r.data, &mut s.db)?;
    let aip: Vec<u8> = s.get(0x82).unwrap_or(&[]).to_vec();
    let cpr: Option<Vec<u8>> = s.get(0x9F71).map(|c| c.to_vec());
    let cpr = cpr.as_deref();
    if s.get(0x94).map_or(true, |a| a.is_empty()) {
        // without an AFL the card only offers mag-stripe mode, which is not implemented
        return Ok(Outcome::end_application(L2Error::MagstripeNotSupported, 0, Some(Message::InsertSwipeOrTryAnother)));
    }

    read_application_data(s)?;
    check_mandatory(s, &[0x5F24, 0x5A, 0x8C])?;

    // Interface switching requested by the card
    let is_cash = matches!(s.txn.txn_type, 0x01 | 0x17);
    let is_cashback = s.txn.txn_type == 0x09 || s.txn.amount_other > 0;
    if (is_cash && bit(cpr, 1, 3)) || (is_cashback && bit(cpr, 1, 2)) {
        return Ok(Outcome::try_another_interface());
    }

    let terminal_cda = bit(Some(&s.env.terminal.capabilities), 3, 4);
    let cda = common::select_cda(s, Some(&aip), terminal_cda);
    processing_restrictions(s)?;

    let cvm = match cvm_from_cpr(&ttq, cpr) {
        Some(c) => c,
        None => {
            s.db.set(0x9F34, &[0x3F, 0x00, 0x01]);
            return Ok(common::outcome(s, Status::Declined, Cvm::NoCvm, DATA_RECORD_TAGS, L2Error::Ok));
        }
    };
    s.db.set(0x9F34, &cvm_results(cvm));

    if s.txn.amount > cfg.floor_limit {
        s.set_tvr(TVR_FLOOR_LIMIT);
    }
    let online_capable = s.env.terminal.online_capable() && !bit(Some(&ttq), 1, 4);
    let mut ac = terminal_action_analysis(s, &cfg.tac_denial, &cfg.tac_online, &cfg.tac_default, online_capable);
    if cvm == Cvm::OnlinePin && ac == apdu::TC {
        ac = if online_capable { apdu::ARQC } else { apdu::AAC }; // online PIN cannot be approved offline
    }
    let r = common::generate_ac_with_cda(s, ac, cda)?;
    Ok(common::gac_outcome(s, r, cvm, DATA_RECORD_TAGS))
}
