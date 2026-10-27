//! Kernel 4: American Express ExpressPay (EMV Contactless Book C-4), EMV mode.
//! Mirrors `python/openpaykernel/kernels/amex.py`.
//!
//! Enhanced Contactless Reader Capabilities (9F6E) in the PDOL → GPO → READ RECORD → CDA
//! selection → processing restrictions → CVM (mobile CVM or CVM List) → floor limit → TAA →
//! GENERATE AC (CDA).
//!
//! 9F6E bits used: (2,8) mobile CVM, (2,7) online PIN, (2,6) signature, (3,8) offline-only
//! reader, (3,7) CVM required (set per transaction). Mobile CVM Results (9F71) byte 3 = 02 means
//! success. The reader capabilities stay in a local copy because 9F6E is card data for other
//! kernels. Not verified against the official Book C-4 text.

use alloc::vec::Vec;

use crate::apdu::{self, TransmissionError};
use crate::config::bit;
use crate::emvproc::{
    check_mandatory, cvm_list_processing, parse_gpo_response, processing_restrictions, read_application_data,
    terminal_action_analysis, KResult, KernelError, Session, RESULT_UNKNOWN, TVR_FLOOR_LIMIT,
};
use crate::entry_point::{ContactlessKernel, KernelContext};
use crate::kernels::common;
use crate::outcome::{Cvm, L2Error, Message, Outcome};

const DATA_RECORD_TAGS: &[u32] = &[
    0x9F02, 0x9F03, 0x9F26, 0x9F27, 0x9F36, 0x9F10, 0x9F37, 0x95, 0x9A, 0x9C, 0x5F2A, 0x82, 0x9F1A, 0x9F33, 0x9F34,
    0x9F35, 0x9F6E, 0x9F71, 0x5A, 0x5F34, 0x57, 0x5F24, 0x84, 0x9F06,
];

const DEFAULT_READER_CAPABILITIES: [u8; 4] = [0xD8, 0xE0, 0x00, 0x03];

pub struct AmexKernel;

impl ContactlessKernel for AmexKernel {
    fn kernel_id(&self) -> u32 {
        4
    }

    fn start(&self, ctx: &mut KernelContext<'_, '_>) -> Result<Outcome, TransmissionError> {
        let ecrc = reader_capabilities(ctx);
        let mut s = Session::new(ctx.env, ctx.aid, ctx.txn, ctx.chan);
        match run(ctx.fci, &ctx.candidate.adf_name, ecrc, &mut s) {
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

/// 9F6E for this transaction: configuration value plus the per-transaction bits.
fn reader_capabilities(ctx: &KernelContext<'_, '_>) -> [u8; 4] {
    let mut ecrc = [0u8; 4];
    match ctx.aid.extra.get(&0x9F6E) {
        Some(v) => {
            for (i, b) in v.iter().take(4).enumerate() {
                ecrc[i] = *b;
            }
        }
        None => ecrc = DEFAULT_READER_CAPABILITIES,
    }
    ecrc[2] &= 0x3F;
    if matches!(ctx.env.terminal.terminal_type & 0x0F, 3 | 6) {
        ecrc[2] |= 0x80; // offline-only reader
    }
    if ctx.pre.cvm_required_limit_exceeded {
        ecrc[2] |= 0x40; // CVM required
    }
    ecrc
}

fn run(fci: &[u8], adf_name: &[u8], ecrc: [u8; 4], s: &mut Session) -> KResult<Outcome> {
    let cfg = s.aid;
    if !common::store_fci(s, fci, adf_name)? {
        return Ok(Outcome::select_next(L2Error::ParsingError, 0));
    }
    s.db.set(0x9F6E, &ecrc);
    let e = Some(&ecrc[..]);

    // GET PROCESSING OPTIONS
    let pdol = s.get(0x9F38).unwrap_or(&[]).to_vec();
    s.pdol_data = s.build_dol(&pdol)?;
    let r = s.exchange(&apdu::get_processing_options(&s.pdol_data))?;
    match r.sw {
        0x6984 => return Ok(Outcome::try_another_interface()),
        0x9000 => {}
        sw => return Ok(Outcome::select_next(L2Error::StatusBytes, sw)),
    }
    parse_gpo_response(&r.data, &mut s.db)?;
    let aip: Vec<u8> = s.get(0x82).unwrap_or(&[]).to_vec();
    if !bit(Some(&aip), 2, 8) || s.get(0x94).map_or(true, |a| a.is_empty()) {
        return Ok(Outcome::end_application(L2Error::MagstripeNotSupported, 0, Some(Message::InsertSwipeOrTryAnother)));
    }

    read_application_data(s)?;
    check_mandatory(s, &[0x5F24, 0x5A, 0x8C, 0x8D])?;
    let terminal_cda = bit(Some(&s.env.terminal.capabilities), 3, 4);
    let cda = common::select_cda(s, Some(&aip), terminal_cda);
    processing_restrictions(s)?;

    let cvm_required = bit(e, 3, 7);
    let mobile: Option<Vec<u8>> = s.get(0x9F71).map(|m| m.to_vec());
    let cvm = match mobile {
        Some(m) if m.len() == 3 && bit(e, 2, 8) && m[2] == 0x02 => {
            s.db.set(0x9F34, &m);
            Cvm::ConfirmationCodeVerified
        }
        _ => {
            let mut caps = s.env.terminal.capabilities;
            // below the CVM limit only "No CVM required" is offered; above it, what the reader supports
            caps[1] = if cvm_required {
                (if bit(e, 2, 7) { 0x40 } else { 0 }) | (if bit(e, 2, 6) { 0x20 } else { 0 })
            } else {
                0x08
            };
            let res = cvm_list_processing(s, caps, &mut |_, _| Ok(RESULT_UNKNOWN))?;
            s.db.set(0x9F34, &res.results);
            if res.online_pin {
                Cvm::OnlinePin
            } else if res.signature {
                Cvm::Signature
            } else {
                Cvm::NoCvm
            }
        }
    };

    if s.txn.amount > cfg.floor_limit {
        s.set_tvr(TVR_FLOOR_LIMIT);
    }
    let online_capable = s.env.terminal.online_capable() && !bit(e, 3, 8);
    let mut ac = terminal_action_analysis(s, &cfg.tac_denial, &cfg.tac_online, &cfg.tac_default, online_capable);
    if cvm == Cvm::OnlinePin && ac == apdu::TC {
        ac = if online_capable { apdu::ARQC } else { apdu::AAC }; // online PIN cannot be approved offline
    }
    let r = common::generate_ac_with_cda(s, ac, cda)?;
    Ok(common::gac_outcome(s, r, cvm, DATA_RECORD_TAGS))
}
