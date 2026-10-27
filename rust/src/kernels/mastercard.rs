//! Kernel 2: Mastercard (EMV Contactless Book C-2), EMV mode.
//! Mirrors `python/openpaykernel/kernels/mastercard.py`.

use alloc::vec::Vec;

use crate::apdu::{self, TransmissionError};
use crate::config::{bcd_to_int, bit};
use crate::emvproc::{
    card_err, check_mandatory, cvm_list_processing, parse_gpo_response, processing_restrictions, read_application_data,
    terminal_action_analysis, KResult, KernelError, Session, RESULT_UNKNOWN, TVR_FLOOR_LIMIT,
};
use crate::entry_point::{ContactlessKernel, KernelContext};
use crate::kernels::common;
use crate::outcome::{Cvm, L2Error, Message, Outcome};

const DATA_RECORD_TAGS: &[u32] = &[
    0x9F02, 0x9F03, 0x9F26, 0x5F24, 0x82, 0x50, 0x5A, 0x5F34, 0x9F12, 0x9F36, 0x9F07, 0x9F09, 0x84, 0x9F27, 0x9F34,
    0x9F1E, 0x9F10, 0x9F33, 0x9F1A, 0x9F35, 0x95, 0x57, 0x9F53, 0x5F2A, 0x9A, 0x9C, 0x9F37, 0x9F6E, 0x9F7C, 0x9F06,
];

// Kernel Configuration (DF811B) byte 1 bits
const KC_EMV_MODE_NOT_SUPPORTED: u8 = 7;
const KC_ON_DEVICE_CVM_SUPPORTED: u8 = 6;

pub struct MastercardKernel;

impl ContactlessKernel for MastercardKernel {
    fn kernel_id(&self) -> u32 {
        2
    }

    fn start(&self, ctx: &mut KernelContext<'_, '_>) -> Result<Outcome, TransmissionError> {
        let mut s = Session::new(ctx.env, ctx.aid, ctx.txn, ctx.chan);
        match run(ctx.fci, &ctx.candidate.adf_name, &mut s) {
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

fn run(fci_raw: &[u8], adf_name: &[u8], s: &mut Session) -> KResult<Outcome> {
    let cfg = s.aid;
    if !common::store_fci(s, fci_raw, adf_name)? {
        return Ok(Outcome::select_next(L2Error::ParsingError, 0));
    }
    let kc: Vec<u8> = s.get(0xDF811B).unwrap_or(&[0x20]).to_vec();
    let kc = Some(kc.as_slice());

    // 1. Initiate application processing
    let pdol = s.get(0x9F38).unwrap_or(&[]).to_vec();
    s.pdol_data = s.build_dol(&pdol)?;
    let r = s.exchange(&apdu::get_processing_options(&s.pdol_data))?;
    if !r.ok() {
        return Ok(Outcome::select_next(L2Error::StatusBytes, r.sw));
    }
    parse_gpo_response(&r.data, &mut s.db)?;
    let aip = s.get(0x82).unwrap_or(&[]).to_vec();
    let aip = Some(aip.as_slice());
    // EMV mode needs AIP byte 2 bit 8 and must not be disabled in the Kernel Configuration
    if !bit(aip, 2, 8) || bit(kc, 1, KC_EMV_MODE_NOT_SUPPORTED) {
        return Ok(Outcome::end_application(L2Error::MagstripeNotSupported, 0, Some(Message::InsertSwipeOrTryAnother)));
    }

    // 2. Read application data
    if s.get(0x94).map_or(true, |a| a.is_empty()) {
        return card_err();
    }
    read_application_data(s)?;
    check_mandatory(s, &[0x5F24, 0x5A, 0x8C, 0x8D])?;

    // 3. ODA selection: C-2 supports only CDA
    let security_cda = bit(Some(s.get(0xDF811F).unwrap_or(&[0x08])), 1, 4);
    let cda = common::select_cda(s, aip, security_cda);

    // 4. Processing restrictions
    processing_restrictions(s)?;

    // 5. Cardholder verification
    let amount = s.txn.amount;
    let cvm_limit = cfg.cvm_required_limit.unwrap_or_else(|| bcd_to_int(s.get(0xDF8126).unwrap_or(&[0])));
    let on_device = bit(aip, 1, 2) && bit(kc, 1, KC_ON_DEVICE_CVM_SUPPORTED);
    let cvm = if on_device && amount > cvm_limit {
        s.db.set(0x9F34, &[0x01, 0x00, 0x02]);
        Cvm::ConfirmationCodeVerified
    } else {
        let mut caps = [0u8; 3];
        let cur = s.get(0x9F33).unwrap_or(&[0; 3]);
        for (i, c) in cur.iter().take(3).enumerate() {
            caps[i] = *c;
        }
        caps[1] = s
            .get(if amount > cvm_limit { 0xDF8118 } else { 0xDF8119 })
            .and_then(|v| v.first().copied())
            .unwrap_or(0x08);
        s.db.set(0x9F33, &caps);
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

    // 6. Reader limits and floor limit
    let limit = if on_device { cfg.cl_transaction_limit_cdcvm } else { cfg.cl_transaction_limit }
        .or_else(|| s.get(if on_device { 0xDF8125 } else { 0xDF8124 }).map(bcd_to_int));
    if limit.is_some_and(|l| amount > l) {
        return Ok(Outcome::select_next(L2Error::MaxLimitExceeded, 0));
    }
    let floor = s.get(0xDF8123).map(bcd_to_int).unwrap_or(cfg.floor_limit);
    if amount > floor {
        s.set_tvr(TVR_FLOOR_LIMIT);
    }

    // 7. Terminal action analysis
    let tac = |tag: u32, dflt: &[u8; 5]| s.get(tag).map(|v| v.to_vec()).unwrap_or(dflt.to_vec());
    let (tac_default, tac_denial, tac_online) =
        (tac(0xDF8120, &cfg.tac_default), tac(0xDF8121, &cfg.tac_denial), tac(0xDF8122, &cfg.tac_online));
    let online_capable = s.env.terminal.online_capable();
    let ac_type = terminal_action_analysis(s, &tac_denial, &tac_online, &tac_default, online_capable);

    // 8. GENERATE AC (with CDA when selected)
    let r = common::generate_ac_with_cda(s, ac_type, cda)?;
    Ok(common::gac_outcome(s, r, cvm, DATA_RECORD_TAGS))
}
