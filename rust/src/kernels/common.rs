//! Steps shared by the contactless kernels that finish with GENERATE AC (kernels 2, 4, 5, 6).
//! Mirrors `python/openpaykernel/kernels/common.py`.

use alloc::vec::Vec;

use crate::apdu;
use crate::config::bit;
use crate::emvproc::{
    card_err, parse_generate_ac, retrieve_icc_pk, KResult, Session, TVR_CDA_FAILED, TVR_ODA_NOT_PERFORMED,
};
use crate::oda;
use crate::outcome::{Cvm, L2Error, Message, Outcome, Status};
use crate::tlv;

/// Result of [`generate_ac_with_cda`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GacResult {
    /// Cryptogram type returned by the card (apdu::AAC / TC / ARQC).
    Cid(u8),
    /// CDA verification failed; TVR "CDA failed" is set.
    CdaFailed,
    /// GENERATE AC answered with an error status word.
    StatusWord(u16),
}

/// Store the FCI of the selected application. Ok(false) = not an FCI template (select next).
pub fn store_fci(s: &mut Session, fci_raw: &[u8], adf_name: &[u8]) -> KResult<bool> {
    let fci = tlv::parse(fci_raw)?;
    if fci.first().map(|t| t.tag) != Some(0x6F) {
        return Ok(false);
    }
    s.db.store_card_data(&fci)?;
    s.db.set(0x9F06, adf_name);
    Ok(true)
}

/// CDA is used when card and terminal support it. A missing CA key marks CDA as failed.
pub fn select_cda(s: &mut Session, aip: Option<&[u8]>, terminal_supports_cda: bool) -> bool {
    if !(bit(aip, 1, 1) && terminal_supports_cda) {
        s.set_tvr(TVR_ODA_NOT_PERFORMED);
        return false;
    }
    let rid: Vec<u8> = s.get(0x9F06).unwrap_or(&[]).iter().take(5).copied().collect();
    let found = match s.get(0x8F) {
        Some(idx) if !idx.is_empty() => s.env.capks.find(&rid, idx[0], Some(&s.txn.date)).is_some(),
        _ => false,
    };
    if !found {
        s.set_tvr(TVR_CDA_FAILED);
    }
    true
}

/// Send GENERATE AC with CDOL1 (CDA requested when possible) and verify the response.
pub fn generate_ac_with_cda(s: &mut Session, ac_type: u8, cda: bool) -> KResult<GacResult> {
    let request_cda = cda && !s.tvr_bit(TVR_CDA_FAILED) && ac_type != apdu::AAC;
    let cdol1 = s.get(0x8C).unwrap_or(&[]).to_vec();
    s.cdol1_data = s.build_dol(&cdol1)?;
    let p1 = ac_type | if request_cda { apdu::CDA_REQUESTED } else { 0 };
    let r = s.exchange(&apdu::generate_ac(p1, &s.cdol1_data))?;
    if !r.ok() {
        return Ok(GacResult::StatusWord(r.sw));
    }
    let children = parse_generate_ac(&r.data, &mut s.db)?;
    let cid_byte = s.get(0x9F27).and_then(|c| c.first().copied()).unwrap_or(0);
    let cid = cid_byte & 0xC0;
    if request_cda && cid != apdu::AAC {
        let sdad = match s.get(0x9F4B) {
            Some(v) => v.to_vec(),
            None => {
                s.set_tvr(TVR_CDA_FAILED);
                return Ok(GacResult::CdaFailed);
            }
        };
        let verified = retrieve_icc_pk(s).and_then(|icc| {
            let mut tx = s.pdol_data.clone();
            tx.extend_from_slice(&s.cdol1_data);
            for (tag, enc) in &children {
                if *tag != 0x9F4B {
                    tx.extend_from_slice(enc);
                }
            }
            oda::verify_cda(&icc, &sdad, s.get(0x9F37).unwrap_or(&[]), cid_byte, &tx)
        });
        match verified {
            Ok((ac, dd)) => {
                s.db.set(0x9F26, &ac);
                s.db.set(0x9F4C, oda::icc_dynamic_number(&dd));
            }
            Err(_) => {
                s.set_tvr(TVR_CDA_FAILED);
                return Ok(GacResult::CdaFailed);
            }
        }
    } else if !s.db.has(0x9F26) {
        return card_err();
    }
    Ok(GacResult::Cid(cid))
}

pub fn status_for(cid: u8) -> Status {
    match cid {
        apdu::TC => Status::Approved,
        apdu::ARQC => Status::OnlineRequest,
        _ => Status::Declined,
    }
}

pub fn outcome(s: &mut Session, status: Status, cvm: Cvm, record_tags: &[u32], l2: L2Error) -> Outcome {
    s.sync();
    let msg = match status {
        Status::Approved if cvm == Cvm::Signature => Message::ApprovedSign,
        Status::Approved => Message::Approved,
        Status::Declined => Message::NotAuthorised,
        _ => Message::Authorising,
    };
    let mut o = Outcome::new(status, cvm, Some(msg));
    o.error.l2 = l2;
    o.data_record = s.db.subset(record_tags);
    o
}

/// The outcome for a [`GacResult`] once GENERATE AC has been sent.
pub fn gac_outcome(s: &mut Session, r: GacResult, cvm: Cvm, record_tags: &[u32]) -> Outcome {
    match r {
        GacResult::Cid(cid) => outcome(s, status_for(cid), cvm, record_tags, L2Error::Ok),
        GacResult::CdaFailed => outcome(s, Status::Declined, cvm, record_tags, L2Error::CamFailed),
        GacResult::StatusWord(sw) => Outcome::end_application(L2Error::StatusBytes, sw, Some(Message::ProcessingError)),
    }
}
