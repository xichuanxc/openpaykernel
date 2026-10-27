//! Kernel 5: JCB J/Speedy (EMV Contactless Book C-5), EMV mode.
//! Mirrors `python/openpaykernel/kernels/jcb.py`.
//!
//! Terminal Interchange Profile (9F53) in the PDOL → GPO → READ RECORD → CDA selection →
//! processing restrictions → CVM (on-device CVM or CVM List with the TIP's capabilities) →
//! floor limit → TAA → GENERATE AC (CDA).
//!
//! TIP byte 1: (1,8) CVM required (per transaction), (1,7) signature, (1,6) online PIN,
//! (1,5) on-device CVM, (1,2) contact chip supported. Not verified against the official
//! Book C-5 text. Legacy (mag-stripe) mode is not implemented.

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
    0x9F35, 0x9F53, 0x5A, 0x5F34, 0x57, 0x5F24, 0x84, 0x9F06,
];

const DEFAULT_TIP: [u8; 3] = [0x72, 0x00, 0x00];

pub struct JcbKernel;

impl ContactlessKernel for JcbKernel {
    fn kernel_id(&self) -> u32 {
        5
    }

    fn start(&self, ctx: &mut KernelContext<'_, '_>) -> Result<Outcome, TransmissionError> {
        let tip = terminal_interchange_profile(ctx);
        let mut s = Session::new(ctx.env, ctx.aid, ctx.txn, ctx.chan);
        match run(ctx.fci, &ctx.candidate.adf_name, tip, &mut s) {
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

/// 9F53 for this transaction: configuration value plus the CVM-required bit.
fn terminal_interchange_profile(ctx: &KernelContext<'_, '_>) -> [u8; 3] {
    let mut tip = [0u8; 3];
    match ctx.aid.extra.get(&0x9F53) {
        Some(v) => {
            for (i, b) in v.iter().take(3).enumerate() {
                tip[i] = *b;
            }
        }
        None => tip = DEFAULT_TIP,
    }
    tip[0] &= 0x7F;
    if ctx.pre.cvm_required_limit_exceeded {
        tip[0] |= 0x80;
    }
    tip
}

fn run(fci: &[u8], adf_name: &[u8], tip: [u8; 3], s: &mut Session) -> KResult<Outcome> {
    let cfg = s.aid;
    if !common::store_fci(s, fci, adf_name)? {
        return Ok(Outcome::select_next(L2Error::ParsingError, 0));
    }
    s.db.set(0x9F53, &tip);
    let t = Some(&tip[..]);

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
    let a = Some(&aip[..]);
    if !bit(a, 2, 8) || s.get(0x94).map_or(true, |x| x.is_empty()) {
        // legacy (mag-stripe) mode is not implemented
        return Ok(Outcome::end_application(L2Error::MagstripeNotSupported, 0, Some(Message::InsertSwipeOrTryAnother)));
    }

    read_application_data(s)?;
    check_mandatory(s, &[0x5F24, 0x5A, 0x8C])?;
    let terminal_cda = bit(Some(&s.env.terminal.capabilities), 3, 4);
    let cda = common::select_cda(s, a, terminal_cda);
    processing_restrictions(s)?;

    let cvm_required = bit(t, 1, 8);
    let cvm = if cvm_required && bit(a, 1, 2) && bit(t, 1, 5) {
        s.db.set(0x9F34, &[0x01, 0x00, 0x02]);
        Cvm::ConfirmationCodeVerified
    } else {
        let mut caps = s.env.terminal.capabilities;
        // below the CVM limit only "No CVM required" is offered; above it, what the TIP allows
        caps[1] = if cvm_required {
            (if bit(t, 1, 6) { 0x40 } else { 0 }) | (if bit(t, 1, 7) { 0x20 } else { 0 })
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
    };

    if s.txn.amount > cfg.floor_limit {
        s.set_tvr(TVR_FLOOR_LIMIT);
    }
    let online_capable = s.env.terminal.online_capable();
    let mut ac = terminal_action_analysis(s, &cfg.tac_denial, &cfg.tac_online, &cfg.tac_default, online_capable);
    if cvm == Cvm::OnlinePin && ac == apdu::TC {
        ac = if online_capable { apdu::ARQC } else { apdu::AAC }; // online PIN cannot be approved offline
    }
    let r = common::generate_ac_with_cda(s, ac, cda)?;
    Ok(common::gac_outcome(s, r, cvm, DATA_RECORD_TAGS))
}
