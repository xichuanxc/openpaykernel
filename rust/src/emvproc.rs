//! EMV processing steps shared by the contact kernel and the contactless EMV-mode kernels
//! (EMV Book 3 section 10, Book 4 section 6). Mirrors `python/openpaykernel/emvproc.py`.

use alloc::vec::Vec;

use crate::apdu::{self, Channel, Response, TransmissionError};
use crate::config::{bcd_to_int, bit, AidConfig, Environment, Transaction};
use crate::dol::{self, MAX_COMMAND_DATA};
use crate::oda::{self, OdaError, PublicKey};
use crate::tags;
use crate::tlv::{self, TlvDb, TlvError};

/// Why a kernel step stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    /// The card's data or status words violate the specification (SW attached when relevant).
    Card(u16),
    /// Malformed BER-TLV in a card response.
    Parse,
    /// Level-1 error from the reader.
    Transmission,
}

impl From<TransmissionError> for KernelError {
    fn from(_: TransmissionError) -> Self {
        KernelError::Transmission
    }
}

impl From<TlvError> for KernelError {
    fn from(_: TlvError) -> Self {
        KernelError::Parse
    }
}

pub type KResult<T> = Result<T, KernelError>;

pub fn card_err<T>() -> KResult<T> {
    Err(KernelError::Card(0))
}

// --- TVR / TSI bit positions (Book 3 Annex C5/C6): (byte, bit) ---------------------------
pub const TVR_ODA_NOT_PERFORMED: (usize, u8) = (1, 8);
pub const TVR_SDA_FAILED: (usize, u8) = (1, 7);
pub const TVR_ICC_DATA_MISSING: (usize, u8) = (1, 6);
pub const TVR_EXCEPTION_FILE: (usize, u8) = (1, 5);
pub const TVR_DDA_FAILED: (usize, u8) = (1, 4);
pub const TVR_CDA_FAILED: (usize, u8) = (1, 3);
pub const TVR_SDA_SELECTED: (usize, u8) = (1, 2);
pub const TVR_APP_VERSION_DIFFERS: (usize, u8) = (2, 8);
pub const TVR_EXPIRED: (usize, u8) = (2, 7);
pub const TVR_NOT_EFFECTIVE: (usize, u8) = (2, 6);
pub const TVR_SERVICE_NOT_ALLOWED: (usize, u8) = (2, 5);
pub const TVR_NEW_CARD: (usize, u8) = (2, 4);
pub const TVR_CVM_FAILED: (usize, u8) = (3, 8);
pub const TVR_UNRECOGNISED_CVM: (usize, u8) = (3, 7);
pub const TVR_PIN_TRY_LIMIT: (usize, u8) = (3, 6);
pub const TVR_PIN_PAD_MISSING: (usize, u8) = (3, 5);
pub const TVR_PIN_NOT_ENTERED: (usize, u8) = (3, 4);
pub const TVR_ONLINE_PIN: (usize, u8) = (3, 3);
pub const TVR_FLOOR_LIMIT: (usize, u8) = (4, 8);
pub const TVR_LCOL_EXCEEDED: (usize, u8) = (4, 7);
pub const TVR_UCOL_EXCEEDED: (usize, u8) = (4, 6);
pub const TVR_RANDOM_ONLINE: (usize, u8) = (4, 5);
pub const TVR_MERCHANT_FORCED_ONLINE: (usize, u8) = (4, 4);
pub const TVR_DEFAULT_TDOL: (usize, u8) = (5, 8);
pub const TVR_ISSUER_AUTH_FAILED: (usize, u8) = (5, 7);
pub const TVR_SCRIPT_FAILED_BEFORE: (usize, u8) = (5, 6);
pub const TVR_SCRIPT_FAILED_AFTER: (usize, u8) = (5, 5);

pub const TSI_ODA: (usize, u8) = (1, 8);
pub const TSI_CVM: (usize, u8) = (1, 7);
pub const TSI_CARD_RISK: (usize, u8) = (1, 6);
pub const TSI_ISSUER_AUTH: (usize, u8) = (1, 5);
pub const TSI_TRM: (usize, u8) = (1, 4);
pub const TSI_SCRIPT: (usize, u8) = (1, 3);

/// Mutable state of one transaction on one application.
pub struct Session<'a, 'r> {
    pub env: &'a Environment,
    pub aid: &'a AidConfig,
    pub txn: &'a Transaction,
    pub chan: &'a mut Channel<'r>,
    pub db: TlvDb,
    pub tvr: [u8; 5],
    pub tsi: [u8; 2],
    pub static_data: Vec<u8>,
    pub static_invalid: bool,
    pub pdol_data: Vec<u8>,
    pub cdol1_data: Vec<u8>,
}

impl<'a, 'r> Session<'a, 'r> {
    pub fn new(env: &'a Environment, aid: &'a AidConfig, txn: &'a Transaction, chan: &'a mut Channel<'r>) -> Self {
        let mut db = TlvDb::new();
        for (t, v) in env.terminal.tags() {
            db.set(t, &v);
        }
        for (t, v) in txn.tags() {
            db.set(t, &v);
        }
        for (t, v) in &aid.extra {
            db.set(*t, v);
        }
        db.set(0x9F09, &aid.app_version);
        db.set(0x9F1B, &(aid.floor_limit as u32).to_be_bytes());
        db.set(0x9F37, &env.random(4));
        let mut s = Session {
            env,
            aid,
            txn,
            chan,
            db,
            tvr: [0; 5],
            tsi: [0; 2],
            static_data: Vec::new(),
            static_invalid: false,
            pdol_data: Vec::new(),
            cdol1_data: Vec::new(),
        };
        s.sync();
        s
    }

    pub fn sync(&mut self) {
        self.db.set(0x95, &self.tvr);
        self.db.set(0x9B, &self.tsi);
    }

    pub fn set_tvr(&mut self, (byte, b): (usize, u8)) {
        self.tvr[byte - 1] |= 1 << (b - 1);
        self.sync();
    }

    pub fn tvr_bit(&self, (byte, b): (usize, u8)) -> bool {
        self.tvr[byte - 1] & (1 << (b - 1)) != 0
    }

    pub fn set_tsi(&mut self, (byte, b): (usize, u8)) {
        self.tsi[byte - 1] |= 1 << (b - 1);
        self.sync();
    }

    /// Build DOL data from the session database; malformed or oversized → card error.
    pub fn build_dol(&mut self, d: &[u8]) -> KResult<Vec<u8>> {
        self.sync();
        let out = dol::build_dol(d, &self.db).map_err(|_| KernelError::Card(0))?;
        if out.len() > MAX_COMMAND_DATA {
            return card_err();
        }
        Ok(out)
    }

    pub fn exchange(&mut self, capdu: &[u8]) -> KResult<Response> {
        Ok(self.chan.exchange(capdu)?)
    }

    pub fn get(&self, tag: u32) -> Option<&[u8]> {
        self.db.get(tag)
    }
}

// --- Initiate application processing ---------------------------------------------------

pub fn parse_gpo_response(rsp: &[u8], db: &mut TlvDb) -> KResult<()> {
    let nodes = tlv::parse(rsp)?;
    if nodes.len() != 1 {
        return card_err();
    }
    let n = nodes[0];
    match n.tag {
        0x80 => {
            if n.value.len() < 2 || (n.value.len() - 2) % 4 != 0 {
                return card_err();
            }
            db.set(0x82, &n.value[..2]);
            db.set(0x94, &n.value[2..]);
            Ok(())
        }
        0x77 => {
            let kids = tlv::parse(n.value)?;
            db.store_card_data(&kids)?;
            if db.has(0x82) {
                Ok(())
            } else {
                card_err()
            }
        }
        _ => card_err(),
    }
}

pub fn parse_afl(afl: &[u8]) -> KResult<Vec<(u8, u8, u8, u8)>> {
    if afl.len() % 4 != 0 {
        return card_err();
    }
    let mut out = Vec::new();
    for e in afl.chunks(4) {
        let (sfi, first, last, n_oda) = (e[0] >> 3, e[1], e[2], e[3]);
        if !(1..=30).contains(&sfi) || first == 0 || last < first || n_oda > last - first + 1 || e[0] & 0x07 != 0 {
            return card_err();
        }
        out.push((sfi, first, last, n_oda));
    }
    Ok(out)
}

/// READ RECORD loop over the AFL (Book 3 10.2), collecting static data for ODA.
pub fn read_application_data(s: &mut Session) -> KResult<()> {
    let afl = s.get(0x94).unwrap_or(&[]).to_vec();
    for (sfi, first, last, n_oda) in parse_afl(&afl)? {
        for rec_no in first..=last {
            let r = s.exchange(&apdu::read_record(sfi, rec_no))?;
            if !r.ok() {
                return Err(KernelError::Card(r.sw));
            }
            let nodes = tlv::parse(&r.data).map_err(|_| KernelError::Card(0))?;
            let is70 = nodes.len() == 1 && nodes[0].tag == 0x70;
            if sfi <= 10 && !is70 {
                return card_err();
            }
            let mut dup = false;
            let mut found: Vec<(u32, Vec<u8>)> = Vec::new();
            tlv::for_each_primitive(&nodes, &mut |c| {
                if !tags::is_terminal_source(c.tag) {
                    found.push((c.tag, c.value.to_vec()));
                }
            })
            .map_err(|_| KernelError::Card(0))?;
            for (tag, value) in found {
                if s.db.has(tag) {
                    dup = true;
                    break;
                }
                s.db.set(tag, &value);
            }
            if dup {
                return card_err();
            }
            if rec_no - first < n_oda {
                if sfi <= 10 {
                    if is70 {
                        s.static_data.extend_from_slice(nodes[0].value);
                    }
                } else if r.data.first() == Some(&0x70) {
                    s.static_data.extend_from_slice(&r.data);
                } else {
                    s.static_invalid = true;
                }
            }
        }
    }
    Ok(())
}

pub fn check_mandatory(s: &Session, tags: &[u32]) -> KResult<()> {
    if tags.iter().all(|t| s.db.has(*t)) {
        Ok(())
    } else {
        card_err()
    }
}

// --- ODA key chain ---------------------------------------------------------------------

pub fn static_data_to_authenticate(s: &Session) -> Result<Vec<u8>, OdaError> {
    if s.static_invalid {
        return Err(OdaError("record used for ODA is not in a 70 template"));
    }
    let mut out = s.static_data.clone();
    if let Some(list) = s.get(0x9F4A) {
        if !list.is_empty() {
            let tags = tlv::parse_tag_list(list).map_err(|_| OdaError("SDA Tag List malformed"))?;
            if tags != [0x82] {
                return Err(OdaError("SDA Tag List must contain only tag 82"));
            }
            out.extend_from_slice(s.get(0x82).unwrap_or(&[]));
        }
    }
    Ok(out)
}

pub fn retrieve_issuer_pk(s: &Session) -> Result<PublicKey, OdaError> {
    let aid = s.get(0x4F).or_else(|| s.get(0x84)).unwrap_or(&[]);
    let rid = &aid[..aid.len().min(5)];
    let (idx, cert, exp, pan) = match (s.get(0x8F), s.get(0x90), s.get(0x9F32), s.get(0x5A)) {
        (Some(i), Some(c), Some(e), Some(p)) if !i.is_empty() => (i[0], c, e, p),
        _ => return Err(OdaError("issuer certificate data missing")),
    };
    let capk = s.env.capks.find(rid, idx, Some(&s.txn.date)).ok_or(OdaError("CA public key not found"))?;
    oda::recover_issuer_pk(capk, cert, s.get(0x92), exp, pan, &s.txn.date, Some(&s.env.capks))
}

pub fn retrieve_icc_pk(s: &Session) -> Result<PublicKey, OdaError> {
    let issuer = retrieve_issuer_pk(s)?;
    let (cert, exp) = match (s.get(0x9F46), s.get(0x9F47)) {
        (Some(c), Some(e)) => (c, e),
        _ => return Err(OdaError("ICC certificate data missing")),
    };
    let static_data = static_data_to_authenticate(s)?;
    let pan = s.get(0x5A).ok_or(OdaError("PAN missing"))?;
    oda::recover_icc_pk(&issuer, cert, s.get(0x9F48), exp, &static_data, pan, &s.txn.date)
}

// --- Processing restrictions (Book 3 10.4) ---------------------------------------------

/// YYMMDD (as BCD bytes or ASCII digits) → YYYYMMDD; invalid → card error.
pub fn yymmdd_bcd(d: &[u8]) -> KResult<u32> {
    if d.len() != 3 || d.iter().any(|x| x >> 4 > 9 || x & 0x0F > 9) {
        return card_err();
    }
    let v = |x: u8| (x >> 4) as u32 * 10 + (x & 0x0F) as u32;
    let yy = v(d[0]);
    Ok((if yy < 50 { 2000 + yy } else { 1900 + yy }) * 10000 + v(d[1]) * 100 + v(d[2]))
}

pub fn yymmdd_str(d: &str) -> u32 {
    crate::capk::yymmdd_key(d)
}

pub fn pan_hex(pan: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for b in pan {
        s.push_str(&alloc::format!("{:02X}", b));
    }
    while s.ends_with('F') {
        s.pop();
    }
    s
}

pub fn processing_restrictions(s: &mut Session) -> KResult<()> {
    let term = &s.env.terminal;
    if let (Some(c), Some(t)) = (s.get(0x9F08), s.get(0x9F09)) {
        if c != t {
            s.set_tvr(TVR_APP_VERSION_DIFFERS);
        }
    }
    if let Some(auc) = s.get(0x9F07).map(|a| a.to_vec()) {
        if auc.len() >= 2 {
            let a = Some(auc.as_slice());
            let tt = s.txn.txn_type;
            let low = term.terminal_type & 0x0F;
            let is_atm = (4..=6).contains(&low)
                && term.terminal_type >> 4 == 1
                && bit(Some(&term.additional_capabilities), 1, 8);
            if (is_atm && !bit(a, 1, 2)) || (!is_atm && !bit(a, 1, 1)) {
                s.set_tvr(TVR_SERVICE_NOT_ALLOWED);
            }
            if let Some(country) = s.get(0x5F28) {
                let domestic = country == term.country_code;
                if tt == 0x01 || tt == 0x17 {
                    if !bit(a, 1, if domestic { 8 } else { 7 }) {
                        s.set_tvr(TVR_SERVICE_NOT_ALLOWED);
                    }
                } else if tt == 0x00 || tt == 0x09 {
                    let ok = if domestic { bit(a, 1, 6) || bit(a, 1, 4) } else { bit(a, 1, 5) || bit(a, 1, 3) };
                    if !ok {
                        s.set_tvr(TVR_SERVICE_NOT_ALLOWED);
                    }
                    if tt == 0x09 && !bit(a, 2, if domestic { 8 } else { 7 }) {
                        s.set_tvr(TVR_SERVICE_NOT_ALLOWED);
                    }
                }
            }
        }
    }
    let today = yymmdd_str(&s.txn.date);
    if let Some(d) = s.get(0x5F25) {
        if yymmdd_bcd(d)? > today {
            s.set_tvr(TVR_NOT_EFFECTIVE);
        }
    }
    if let Some(d) = s.get(0x5F24) {
        if yymmdd_bcd(d)? < today {
            s.set_tvr(TVR_EXPIRED);
        }
    }
    if let Some(pan) = s.get(0x5A) {
        if s.env.terminal.exception_file.contains(&pan_hex(pan)) {
            s.set_tvr(TVR_EXCEPTION_FILE);
        }
    }
    Ok(())
}

// --- Cardholder verification (Book 3 10.5, Book 4 6.3) ---------------------------------

pub const CVM_FAIL: u8 = 0x00;
pub const CVM_PLAINTEXT_PIN: u8 = 0x01;
pub const CVM_ONLINE_PIN: u8 = 0x02;
pub const CVM_PLAINTEXT_PIN_SIG: u8 = 0x03;
pub const CVM_ENC_PIN: u8 = 0x04;
pub const CVM_ENC_PIN_SIG: u8 = 0x05;
pub const CVM_SIGNATURE: u8 = 0x1E;
pub const CVM_NO_CVM: u8 = 0x1F;

pub const RESULT_UNKNOWN: u8 = 0;
pub const RESULT_FAILED: u8 = 1;
pub const RESULT_SUCCESS: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvmOutcome {
    pub results: [u8; 3],
    pub signature: bool,
    pub online_pin: bool,
    pub offline_pin: bool,
}

impl CvmOutcome {
    fn with(results: [u8; 3]) -> Self {
        CvmOutcome { results, signature: false, online_pin: false, offline_pin: false }
    }
}

pub fn terminal_supports_cvm(caps: &[u8], method: u8) -> bool {
    let c = Some(caps);
    match method & 0x3F {
        CVM_PLAINTEXT_PIN => bit(c, 2, 8),
        CVM_ONLINE_PIN => bit(c, 2, 7),
        CVM_PLAINTEXT_PIN_SIG => bit(c, 2, 8) && bit(c, 2, 6),
        CVM_ENC_PIN => bit(c, 2, 5),
        CVM_ENC_PIN_SIG => bit(c, 2, 5) && bit(c, 2, 6),
        CVM_SIGNATURE => bit(c, 2, 6),
        CVM_NO_CVM => bit(c, 2, 4),
        CVM_FAIL => true,
        _ => false,
    }
}

fn known_cvm(code: u8) -> bool {
    matches!(code, 0x00..=0x05 | CVM_SIGNATURE | CVM_NO_CVM)
}

fn condition_satisfied(s: &Session, cond: u8, x: u64, y: u64, caps: &[u8], method: u8) -> bool {
    let tt = s.txn.txn_type;
    let amount = s.txn.amount;
    let same_ccy = s.get(0x9F42) == Some(&s.txn.currency_code[..]);
    let unattended = !s.env.terminal.attended();
    match cond {
        0x00 => true,
        0x01 => unattended && tt == 0x01,
        0x02 => !matches!(tt, 0x01 | 0x09 | 0x17) && s.txn.amount_other == 0,
        0x03 => terminal_supports_cvm(caps, method),
        0x04 => !unattended && matches!(tt, 0x01 | 0x17),
        0x05 => tt == 0x09 || s.txn.amount_other > 0,
        0x06..=0x09 => {
            if !same_ccy {
                return false;
            }
            let limit = if cond <= 0x07 { x } else { y };
            if cond == 0x06 || cond == 0x08 {
                amount < limit
            } else {
                amount > limit
            }
        }
        _ => false,
    }
}

/// Performs a PIN-based CVM: returns RESULT_SUCCESS / RESULT_FAILED / RESULT_UNKNOWN.
pub type PinFn<'f, 'a, 'r> = &'f mut dyn FnMut(&mut Session<'a, 'r>, u8) -> KResult<u8>;

/// Walk the CVM List.
pub fn cvm_list_processing<'a, 'r>(
    s: &mut Session<'a, 'r>,
    caps: [u8; 3],
    perform: PinFn<'_, 'a, 'r>,
) -> KResult<CvmOutcome> {
    if !bit(s.get(0x82), 1, 5) {
        return Ok(CvmOutcome::with([0x3F, 0x00, 0x00]));
    }
    let list = match s.get(0x8E) {
        Some(l) if l.len() >= 10 => l.to_vec(),
        _ => {
            s.set_tvr(TVR_ICC_DATA_MISSING);
            return Ok(CvmOutcome::with([0x3F, 0x00, 0x00]));
        }
    };
    let x = u32::from_be_bytes([list[0], list[1], list[2], list[3]]) as u64;
    let y = u32::from_be_bytes([list[4], list[5], list[6], list[7]]) as u64;
    let mut last_failed: Option<[u8; 2]> = None;
    let mut i = 8;
    while i + 1 < list.len() {
        let rule = [list[i], list[i + 1]];
        i += 2;
        let (method, cond) = (rule[0], rule[1]);
        let code = method & 0x3F;
        let apply_next = method & 0x40 != 0;
        if !condition_satisfied(s, cond, x, y, &caps, method) {
            continue;
        }
        // Every path below either moves on to the next rule or ends CVM processing as failed.
        if !known_cvm(code) {
            s.set_tvr(TVR_UNRECOGNISED_CVM);
            if apply_next {
                continue;
            }
        } else if code != CVM_FAIL && !terminal_supports_cvm(&caps, code) {
            if apply_next {
                continue;
            }
        } else if code != CVM_FAIL {
            if let Some(out) = perform_cvm(s, code, rule, perform)? {
                return Ok(out);
            }
            last_failed = Some(rule);
            if apply_next {
                continue;
            }
        }
        s.set_tvr(TVR_CVM_FAILED);
        return Ok(CvmOutcome::with([rule[0], rule[1], RESULT_FAILED]));
    }
    s.set_tvr(TVR_CVM_FAILED);
    let r = last_failed.unwrap_or([0x3F, 0x00]);
    Ok(CvmOutcome::with([r[0], r[1], RESULT_FAILED]))
}

fn perform_cvm<'a, 'r>(
    s: &mut Session<'a, 'r>,
    code: u8,
    rule: [u8; 2],
    perform: PinFn<'_, 'a, 'r>,
) -> KResult<Option<CvmOutcome>> {
    match code {
        CVM_NO_CVM => Ok(Some(CvmOutcome::with([rule[0], rule[1], RESULT_SUCCESS]))),
        CVM_SIGNATURE => {
            let mut o = CvmOutcome::with([rule[0], rule[1], RESULT_UNKNOWN]);
            o.signature = true;
            Ok(Some(o))
        }
        CVM_ONLINE_PIN => {
            if perform(s, code)? == RESULT_FAILED {
                return Ok(None);
            }
            s.set_tvr(TVR_ONLINE_PIN);
            let mut o = CvmOutcome::with([rule[0], rule[1], RESULT_UNKNOWN]);
            o.online_pin = true;
            Ok(Some(o))
        }
        _ => {
            if perform(s, code)? == RESULT_SUCCESS {
                let sig = code == CVM_PLAINTEXT_PIN_SIG || code == CVM_ENC_PIN_SIG;
                let mut o = CvmOutcome::with([rule[0], rule[1], if sig { RESULT_UNKNOWN } else { RESULT_SUCCESS }]);
                o.signature = sig;
                o.offline_pin = true;
                Ok(Some(o))
            } else {
                Ok(None)
            }
        }
    }
}

// --- Terminal risk management (Book 3 10.6) --------------------------------------------

fn get_data_value(s: &mut Session, tag: u16) -> KResult<Option<Vec<u8>>> {
    let r = s.exchange(&apdu::get_data(tag))?;
    if !r.ok() || r.data.is_empty() {
        return Ok(None);
    }
    tlv::check(&r.data)?;
    match tlv::find(&r.data, tag as u32) {
        Some(t) => {
            let v = t.value.to_vec();
            s.db.set(tag as u32, &v);
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

pub fn terminal_risk_management(s: &mut Session, floor_limit: Option<u64>) -> KResult<()> {
    let cfg = s.aid;
    let amount = s.txn.amount;
    let floor = floor_limit.unwrap_or(cfg.floor_limit);
    if amount >= floor {
        s.set_tvr(TVR_FLOOR_LIMIT);
    }
    if s.env.terminal.online_capable() && amount < floor && cfg.target_percent != 0 {
        let rnd = (s.env.random(1)[0] % 99) as u64 + 1;
        let pct = if amount < cfg.threshold {
            cfg.target_percent as u64
        } else {
            let span = floor.saturating_sub(cfg.threshold).max(1);
            cfg.target_percent as u64
                + (cfg.max_target_percent as u64).saturating_sub(cfg.target_percent as u64) * (amount - cfg.threshold)
                    / span
        };
        if rnd <= pct {
            s.set_tvr(TVR_RANDOM_ONLINE);
        }
    }
    if s.db.has(0x9F14) && s.db.has(0x9F23) {
        let lcol = s.get(0x9F14).and_then(|v| v.first().copied()).unwrap_or(0) as u64;
        let ucol = s.get(0x9F23).and_then(|v| v.first().copied()).unwrap_or(0) as u64;
        let atc = get_data_value(s, 0x9F36)?;
        let last = get_data_value(s, 0x9F13)?;
        match (atc, last) {
            (Some(atc), Some(last)) => {
                let to_int = |b: &[u8]| b.iter().take(8).fold(0u64, |a, &x| (a << 8) | x as u64);
                let (a, l) = (to_int(&atc), to_int(&last));
                if a <= l {
                    s.set_tvr(TVR_LCOL_EXCEEDED);
                    s.set_tvr(TVR_UCOL_EXCEEDED);
                } else {
                    if a - l > lcol {
                        s.set_tvr(TVR_LCOL_EXCEEDED);
                    }
                    if a - l > ucol {
                        s.set_tvr(TVR_UCOL_EXCEEDED);
                    }
                }
                if l == 0 {
                    s.set_tvr(TVR_NEW_CARD);
                }
            }
            _ => {
                s.set_tvr(TVR_LCOL_EXCEEDED);
                s.set_tvr(TVR_UCOL_EXCEEDED);
                s.set_tvr(TVR_ICC_DATA_MISSING);
            }
        }
    }
    s.set_tsi(TSI_TRM);
    Ok(())
}

// --- Terminal action analysis (Book 3 10.7) --------------------------------------------

fn hit(tvr: &[u8], masks: &[&[u8]]) -> bool {
    masks.iter().any(|m| tvr.iter().zip(m.iter()).any(|(t, m)| t & m != 0))
}

const FF5: [u8; 5] = [0xFF; 5];

/// Returns the cryptogram type to request: apdu::AAC / TC / ARQC.
pub fn terminal_action_analysis(
    s: &mut Session,
    tac_denial: &[u8],
    tac_online: &[u8],
    tac_default: &[u8],
    online_capable: bool,
) -> u8 {
    s.sync();
    let tvr = s.tvr;
    let iac_denial = s.get(0x9F0E).unwrap_or(&[0; 5]).to_vec();
    let iac_online = s.get(0x9F0F).unwrap_or(&FF5).to_vec();
    let iac_default = s.get(0x9F0D).unwrap_or(&FF5).to_vec();
    if hit(&tvr, &[&iac_denial, tac_denial]) {
        return apdu::AAC;
    }
    if s.txn.force_online && online_capable {
        s.set_tvr(TVR_MERCHANT_FORCED_ONLINE);
        return apdu::ARQC;
    }
    if online_capable {
        return if hit(&tvr, &[&iac_online, tac_online]) { apdu::ARQC } else { apdu::TC };
    }
    if hit(&tvr, &[&iac_default, tac_default]) {
        apdu::AAC
    } else {
        apdu::TC
    }
}

/// Book 3 10.7: decision when the terminal is unable to go online.
pub fn default_action(s: &mut Session, tac_default: &[u8]) -> u8 {
    s.sync();
    let iac_default = s.get(0x9F0D).unwrap_or(&FF5).to_vec();
    if hit(&s.tvr, &[&iac_default, tac_default]) {
        apdu::AAC
    } else {
        apdu::TC
    }
}

/// Parse a GENERATE AC response. Returns the re-encoded 77 children (for the CDA hash).
pub fn parse_generate_ac(rsp: &[u8], db: &mut TlvDb) -> KResult<Vec<(u32, Vec<u8>)>> {
    let nodes = tlv::parse(rsp)?;
    if nodes.len() != 1 {
        return card_err();
    }
    let n = nodes[0];
    match n.tag {
        0x80 => {
            let v = n.value;
            if v.len() < 11 {
                return card_err();
            }
            db.set(0x9F27, &v[0..1]);
            db.set(0x9F36, &v[1..3]);
            db.set(0x9F26, &v[3..11]);
            if v.len() > 11 {
                db.set(0x9F10, &v[11..]);
            }
            Ok(Vec::new())
        }
        0x77 => {
            let kids = tlv::parse(n.value)?;
            db.store_card_data(&kids)?;
            if db.get(0x9F27).map_or(true, |c| c.is_empty()) || !db.has(0x9F36) {
                return card_err();
            }
            Ok(kids.iter().map(|c| (c.tag, tlv::encode(c.tag, c.value))).collect())
        }
        _ => card_err(),
    }
}

pub fn amount_from_tag(db: &TlvDb, tag: u32) -> Option<u64> {
    db.get(tag).map(bcd_to_int)
}
