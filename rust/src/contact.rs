//! Contact EMV kernel (EMV Books 1-4). Mirrors `python/openpaykernel/contact.py`.
//!
//! The host answers through [`ContactHost`]: application choice, PIN entry and the online
//! authorisation.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::apdu::{self, Channel, Reader};
use crate::config::{bit, AidConfig, Environment, Transaction};
use crate::crypto::{rsa_public, sha1};
use crate::dol;
use crate::emvproc::*;
use crate::oda::{self, OdaError};
use crate::outcome::{Cvm, L1Error, L2Error, Message, Outcome, Status};
use crate::tlv::{self, Tlv};

pub const PSE: &[u8] = b"1PAY.SYS.DDF01";

#[derive(Debug, Clone)]
pub struct AppCandidate {
    pub aid: Vec<u8>,
    pub label: String,
    pub priority: u8,
    pub needs_confirmation: bool,
    /// Index into `Environment::aids`.
    pub aid_index: usize,
}

#[derive(Debug, Clone)]
pub struct OnlineResponse {
    pub approved: bool,
    /// Authorisation Response Code (8A), two ASCII characters.
    pub arc: [u8; 2],
    /// Issuer Authentication Data (91).
    pub issuer_auth_data: Option<Vec<u8>>,
    /// Concatenated issuer script templates 71/72.
    pub scripts: Vec<u8>,
}

/// Host callbacks for the contact kernel.
pub trait ContactHost {
    /// Return an index into `candidates`, or None to cancel.
    fn choose_application(&mut self, candidates: &[AppCandidate]) -> Option<usize>;
    /// Return the PIN digits, or None to bypass. `tries_left` is None if unknown.
    fn enter_pin(&mut self, online: bool, tries_left: Option<u8>) -> Option<String>;
    /// Authorise online with the given data; None = unable to go online.
    fn go_online(&mut self, data: &BTreeMap<u32, Vec<u8>>) -> Option<OnlineResponse>;
}

const ONLINE_TAGS: &[u32] = &[
    0x9F26, 0x9F27, 0x9F10, 0x9F37, 0x9F36, 0x95, 0x9A, 0x9C, 0x9F02, 0x5F2A, 0x82, 0x9F1A, 0x9F03, 0x9F33, 0x9F34,
    0x9F35, 0x9F1E, 0x84, 0x9F09, 0x9F41, 0x5A, 0x5F34, 0x57, 0x5F24, 0x9F06,
];

#[derive(Debug, Clone)]
pub struct ContactResult {
    pub outcome: Outcome,
    /// Issuer Script Results (9F5B).
    pub script_results: Vec<u8>,
    /// The complete transaction TLV database.
    pub data: BTreeMap<u32, Vec<u8>>,
}

pub struct ContactKernel<H: ContactHost> {
    pub env: Environment,
    pub host: H,
}

fn end(l2: L2Error, sw: u16, db: Option<&tlv::TlvDb>) -> ContactResult {
    ContactResult {
        outcome: Outcome::end_application(l2, sw, Some(Message::ProcessingError)),
        script_results: Vec::new(),
        data: db.map(|d| d.to_map()).unwrap_or_default(),
    }
}

impl<H: ContactHost> ContactKernel<H> {
    pub fn new(env: Environment, host: H) -> Self {
        ContactKernel { env, host }
    }

    /// Run a complete contact transaction. The APDU log is returned in `log` if given.
    pub fn process(
        &mut self,
        reader: &mut dyn Reader,
        txn: &Transaction,
        log: Option<&mut Vec<(Vec<u8>, Vec<u8>)>>,
    ) -> ContactResult {
        let mut chan = Channel::new(reader);
        let result = match run(&self.env, &mut self.host, &mut chan, txn) {
            Ok(r) => r,
            Err(()) => {
                // card removed, timeout, ... (Level 1)
                let mut o = Outcome::end_application(L2Error::Ok, 0, Some(Message::ProcessingError));
                o.error.l1 = L1Error::Transmission;
                ContactResult { outcome: o, script_results: Vec::new(), data: BTreeMap::new() }
            }
        };
        if let Some(l) = log {
            l.append(&mut chan.log);
        }
        result
    }
}

/// Err(()) = Level-1 transmission error.
fn run<H: ContactHost>(
    env: &Environment,
    host: &mut H,
    chan: &mut Channel,
    txn: &Transaction,
) -> Result<ContactResult, ()> {
    let mut cands = match build_candidate_list(env, chan) {
        Ok(c) => c,
        Err(KernelError::Transmission) => return Err(()),
        Err(KernelError::Card(sw)) => return Ok(end(L2Error::CardDataError, sw, None)),
        Err(KernelError::Parse) => return Ok(end(L2Error::CardDataError, 0, None)),
    };
    while !cands.is_empty() {
        let idx = if cands.len() == 1 && !cands[0].needs_confirmation {
            0
        } else {
            match host.choose_application(&cands) {
                Some(i) if i < cands.len() => i,
                _ => return Ok(end(L2Error::EmptyCandidateList, 0, None)),
            }
        };
        let cand = cands[idx].clone();
        let r = chan.exchange(&apdu::select(&cand.aid, true)).map_err(|_| ())?;
        if !r.ok() {
            cands.remove(idx);
            continue;
        }
        let aid = &env.aids[cand.aid_index];
        let mut s = Session::new(env, aid, txn, &mut *chan);
        match process_app(&mut s, host, &r.data) {
            Ok(Some(res)) => return Ok(res),
            Ok(None) => {
                cands.remove(idx); // GPO 6985: try another application
                continue;
            }
            Err(KernelError::Transmission) => return Err(()),
            Err(KernelError::Card(sw)) => return Ok(end(L2Error::CardDataError, sw, Some(&s.db))),
            Err(KernelError::Parse) => return Ok(end(L2Error::ParsingError, 0, Some(&s.db))),
        }
    }
    Ok(end(L2Error::EmptyCandidateList, 0, None))
}

// ------------------------------------------------------------------ selection (Book 1 12)

fn match_cfg(env: &Environment, aid: &[u8]) -> Option<usize> {
    env.aids.iter().position(|c| c.matches(aid))
}

fn candidate(aid: &[u8], node: &Tlv, aid_index: usize) -> AppCandidate {
    let label = node.find(0x50).map_or_else(
        || aid.iter().map(|b| alloc::format!("{:02X}", b)).collect(),
        |l| l.value.iter().map(|&c| if c.is_ascii() { c as char } else { '\u{FFFD}' }).collect(),
    );
    let p = node.find(0x87).and_then(|p| p.value.first().copied()).unwrap_or(0);
    AppCandidate { aid: aid.to_vec(), label, priority: p & 0x0F, needs_confirmation: p & 0x80 != 0, aid_index }
}

pub fn build_candidate_list(env: &Environment, chan: &mut Channel) -> KResult<Vec<AppCandidate>> {
    let mut cands = pse(env, chan)?;
    if cands.is_empty() {
        cands = list_of_aids(env, chan)?;
    }
    cands.sort_by_key(|c| (c.priority == 0, c.priority));
    Ok(cands)
}

fn pse(env: &Environment, chan: &mut Channel) -> KResult<Vec<AppCandidate>> {
    let r = chan.exchange(&apdu::select(PSE, true))?;
    if r.sw == 0x6A81 {
        return Err(KernelError::Card(r.sw)); // card blocked
    }
    if !r.ok() || tlv::check(&r.data).is_err() {
        return Ok(Vec::new());
    }
    let sfi = match tlv::find(&r.data, 0x88) {
        Some(t) if t.value.len() == 1 && (1..=30).contains(&t.value[0]) => t.value[0],
        _ => return Ok(Vec::new()),
    };
    let mut cands = Vec::new();
    for rec in 1..=255u8 {
        let rr = chan.exchange(&apdu::read_record(sfi, rec))?;
        if rr.sw == 0x6A83 {
            break;
        }
        if !rr.ok() {
            return Ok(Vec::new());
        }
        let nodes = match tlv::parse(&rr.data) {
            Ok(n) => n,
            Err(_) => return Ok(Vec::new()),
        };
        match nodes.first() {
            Some(t70) if t70.tag == 0x70 => {
                for e in t70.children().flatten() {
                    if e.tag != 0x61 {
                        continue;
                    }
                    if let Some(aid) = e.find(0x4F) {
                        if let Some(i) = match_cfg(env, aid.value) {
                            cands.push(candidate(aid.value, &e, i));
                        }
                    }
                }
            }
            _ => return Ok(Vec::new()),
        }
    }
    Ok(cands)
}

fn list_of_aids(env: &Environment, chan: &mut Channel) -> KResult<Vec<AppCandidate>> {
    let mut cands = Vec::new();
    for (i, cfg) in env.aids.iter().enumerate() {
        let mut first = true;
        loop {
            let r = chan.exchange(&apdu::select(&cfg.aid, first))?;
            if r.sw == 0x6A81 && first {
                return Err(KernelError::Card(r.sw));
            }
            if r.sw != 0x9000 && r.sw != 0x6283 {
                break;
            }
            let nodes = match tlv::parse(&r.data) {
                Ok(n) => n,
                Err(_) => break,
            };
            let top = match nodes.first() {
                Some(t) => *t,
                None => break,
            };
            let df = match top.find(0x84) {
                Some(d) => d.value,
                None => break,
            };
            if r.sw == 0x9000 {
                if df == cfg.aid.as_slice() {
                    cands.push(candidate(df, &top, i));
                    break;
                }
                if cfg.partial_match && df.starts_with(&cfg.aid) {
                    cands.push(candidate(df, &top, i));
                }
            }
            if !cfg.partial_match {
                break;
            }
            first = false;
        }
    }
    Ok(cands)
}

// ------------------------------------------------------------------ per application

fn process_app<H: ContactHost>(s: &mut Session, host: &mut H, fci_raw: &[u8]) -> KResult<Option<ContactResult>> {
    let fci = tlv::parse(fci_raw)?;
    let df = match fci.first() {
        Some(top) if top.tag == 0x6F => top.find(0x84).ok_or(KernelError::Card(0))?.value.to_vec(),
        _ => return card_err(),
    };
    s.db.store_card_data(&fci)?;
    s.db.set(0x4F, &df);
    let aid_cfg: &AidConfig = s.aid;
    s.db.set(0x9F06, &aid_cfg.aid);

    // Initiate application processing (Book 3 10.1)
    let pdol = s.get(0x9F38).unwrap_or(&[]).to_vec();
    s.pdol_data = s.build_dol(&pdol)?;
    let r = s.exchange(&apdu::get_processing_options(&s.pdol_data))?;
    if r.sw == 0x6985 {
        return Ok(None);
    }
    if !r.ok() {
        return Err(KernelError::Card(r.sw));
    }
    parse_gpo_response(&r.data, &mut s.db)?;

    // Read application data (Book 3 10.2)
    read_application_data(s)?;
    check_mandatory(s, &[0x5F24, 0x5A, 0x8C, 0x8D])?;
    let aip = s.get(0x82).unwrap_or(&[]).to_vec();
    let aip = Some(aip.as_slice());
    let caps = s.env.terminal.capabilities;

    // Offline data authentication (Book 3 10.3)
    let cda = do_oda(s, aip, &caps)?;
    processing_restrictions(s)?;

    // Cardholder verification (Book 3 10.5)
    let cvm_res = cvm_list_processing(s, caps, &mut |s, m| perform_pin(s, host, m))?;
    s.db.set(0x9F34, &cvm_res.results);
    if bit(aip, 1, 5) {
        s.set_tsi(TSI_CVM);
    }
    let cvm = if cvm_res.online_pin {
        Cvm::OnlinePin
    } else if cvm_res.signature {
        Cvm::Signature
    } else if cvm_res.offline_pin {
        Cvm::OfflinePin
    } else {
        Cvm::NoCvm
    };

    // Terminal risk management (Book 3 10.6)
    if bit(aip, 1, 4) || s.txn.amount >= aid_cfg.floor_limit {
        terminal_risk_management(s, None)?;
    }

    // Terminal action analysis (Book 3 10.7)
    let online_capable = s.env.terminal.online_capable();
    let ac =
        terminal_action_analysis(s, &aid_cfg.tac_denial, &aid_cfg.tac_online, &aid_cfg.tac_default, online_capable);

    // Card action analysis (Book 3 10.8): first GENERATE AC
    let cdol1 = s.get(0x8C).unwrap_or(&[]).to_vec();
    let cid = generate_ac(s, ac, &cdol1, cda, true)?;
    s.set_tsi(TSI_CARD_RISK);
    match cid {
        None => return Ok(Some(finish(s, Status::Declined, cvm, Vec::new()))),
        Some(apdu::TC) => {
            s.db.set(0x8A, b"Y1");
            return Ok(Some(finish(s, Status::Approved, cvm, Vec::new())));
        }
        Some(apdu::AAC) => {
            s.db.set(0x8A, b"Z1");
            return Ok(Some(finish(s, Status::Declined, cvm, Vec::new())));
        }
        _ => {}
    }

    // Online processing (Book 3 10.9)
    s.sync();
    let rsp = host.go_online(&s.db.subset(ONLINE_TAGS));
    let mut results = Vec::new();
    let final_ac = match &rsp {
        None => {
            let a = default_action(s, &aid_cfg.tac_default);
            s.db.set(0x8A, if a == apdu::TC { b"Y3" } else { b"Z3" });
            a
        }
        Some(rsp) => {
            s.db.set(0x8A, &rsp.arc);
            if let Some(iad) = &rsp.issuer_auth_data {
                s.db.set(0x91, iad);
                let cdol2_has_91 = dol::contains(s.get(0x8D).unwrap_or(&[]), 0x91);
                if bit(aip, 1, 3) && !cdol2_has_91 {
                    let er = s.exchange(&apdu::external_authenticate(iad))?;
                    s.set_tsi(TSI_ISSUER_AUTH);
                    if !er.ok() {
                        s.set_tvr(TVR_ISSUER_AUTH_FAILED);
                    }
                } else if cdol2_has_91 {
                    s.set_tsi(TSI_ISSUER_AUTH);
                }
            }
            results.extend(run_scripts(s, &rsp.scripts, 0x71)?);
            if rsp.approved {
                apdu::TC
            } else {
                apdu::AAC
            }
        }
    };

    // Completion (Book 3 10.11): second GENERATE AC
    let cdol2 = s.get(0x8D).unwrap_or(&[]).to_vec();
    let cid2 = generate_ac(s, final_ac, &cdol2, cda, false)?;
    if let Some(rsp) = &rsp {
        results.extend(run_scripts(s, &rsp.scripts, 0x72)?);
    }
    if !results.is_empty() {
        s.db.set(0x9F5B, &results);
    }
    let status = if cid2 == Some(apdu::TC) { Status::Approved } else { Status::Declined };
    Ok(Some(finish(s, status, cvm, results)))
}

// ------------------------------------------------------------------ ODA

/// Runs SDA/DDA now. Returns true when CDA is to be done with GENERATE AC.
fn do_oda(s: &mut Session, aip: Option<&[u8]>, caps: &[u8; 3]) -> KResult<bool> {
    let c = Some(&caps[..]);
    if bit(aip, 1, 1) && bit(c, 3, 4) {
        s.set_tsi(TSI_ODA);
        if retrieve_icc_pk(s).is_err() {
            s.set_tvr(TVR_CDA_FAILED);
            return Ok(false);
        }
        return Ok(true);
    }
    if bit(aip, 1, 6) && bit(c, 3, 7) {
        s.set_tsi(TSI_ODA);
        match dda(s)? {
            Ok(()) => {}
            Err(_) => s.set_tvr(TVR_DDA_FAILED),
        }
        return Ok(false);
    }
    if bit(aip, 1, 7) && bit(c, 3, 8) {
        s.set_tsi(TSI_ODA);
        s.set_tvr(TVR_SDA_SELECTED);
        let r = (|| {
            let ssad = s.get(0x93).ok_or(OdaError("SSAD missing"))?.to_vec();
            let issuer = retrieve_issuer_pk(s)?;
            oda::verify_sda(&issuer, &ssad, &static_data_to_authenticate(s)?)
        })();
        match r {
            Ok(dac) => s.db.set(0x9F45, &dac),
            Err(_) => s.set_tvr(TVR_SDA_FAILED),
        }
        return Ok(false);
    }
    s.set_tvr(TVR_ODA_NOT_PERFORMED);
    Ok(false)
}

/// Outer Result: card/transmission errors that end the transaction; inner: DDA verdict.
fn dda(s: &mut Session) -> KResult<Result<(), OdaError>> {
    let icc = match retrieve_icc_pk(s) {
        Ok(k) => k,
        Err(e) => return Ok(Err(e)),
    };
    let ddol = match s.get(0x9F49).filter(|d| !d.is_empty()) {
        Some(d) => d.to_vec(),
        None => s.aid.default_ddol.clone(),
    };
    if !dol::contains(&ddol, 0x9F37) {
        return Ok(Err(OdaError("DDOL without unpredictable number")));
    }
    let ddol_data = s.build_dol(&ddol)?;
    let r = s.exchange(&apdu::internal_authenticate(&ddol_data))?;
    if !r.ok() {
        return Ok(Err(OdaError("INTERNAL AUTHENTICATE failed")));
    }
    let nodes = match tlv::parse(&r.data) {
        Ok(n) if !n.is_empty() => n,
        _ => return Ok(Err(OdaError("INTERNAL AUTHENTICATE response malformed"))),
    };
    let n = nodes[0];
    let sdad = if n.tag == 0x80 { n.value.to_vec() } else { n.find(0x9F4B).map_or(Vec::new(), |t| t.value.to_vec()) };
    match oda::verify_dynamic_signature(&icc, &sdad, &ddol_data) {
        Ok(dd) => {
            s.db.set(0x9F4B, &sdad);
            s.db.set(0x9F4C, oda::icc_dynamic_number(&dd));
            Ok(Ok(()))
        }
        Err(e) => Ok(Err(e)),
    }
}

// ------------------------------------------------------------------ PIN

fn perform_pin<H: ContactHost>(s: &mut Session, host: &mut H, method: u8) -> KResult<u8> {
    let caps = Some(&s.env.terminal.capabilities[..]);
    if method == CVM_ONLINE_PIN {
        if host.enter_pin(true, None).is_none() {
            s.set_tvr(TVR_PIN_NOT_ENTERED);
            return Ok(RESULT_FAILED);
        }
        return Ok(RESULT_SUCCESS);
    }
    if !(bit(caps, 2, 8) || bit(caps, 2, 5)) {
        s.set_tvr(TVR_PIN_PAD_MISSING);
        return Ok(RESULT_FAILED);
    }
    let mut tries: Option<u8> = None;
    let r = s.exchange(&apdu::get_data(0x9F17))?;
    if r.ok() {
        if let Some(t) = tlv::find(&r.data, 0x9F17) {
            if let Some(&n) = t.value.first() {
                tries = Some(n);
                if n == 0 {
                    s.set_tvr(TVR_PIN_TRY_LIMIT);
                    return Ok(RESULT_FAILED);
                }
            }
        }
    }
    let enciphered = method == CVM_ENC_PIN || method == CVM_ENC_PIN_SIG;
    loop {
        let pin = match host.enter_pin(false, tries) {
            Some(p) => p,
            None => {
                s.set_tvr(TVR_PIN_NOT_ENTERED);
                return Ok(RESULT_FAILED);
            }
        };
        let block = match apdu::plaintext_pin_block(&pin) {
            Some(b) => b,
            None => return Ok(RESULT_FAILED), // not 4..12 digits
        };
        let cmd = if enciphered {
            match enciphered_verify(s, &block)? {
                Some(c) => c,
                None => return Ok(RESULT_FAILED),
            }
        } else {
            apdu::verify(&block, 0x80)
        };
        let r = s.exchange(&cmd)?;
        if r.ok() {
            return Ok(RESULT_SUCCESS);
        }
        if r.sw >> 4 == 0x63C {
            let n = (r.sw & 0x0F) as u8;
            tries = Some(n);
            if n == 0 {
                s.set_tvr(TVR_PIN_TRY_LIMIT);
                return Ok(RESULT_FAILED);
            }
            continue;
        }
        if r.sw == 0x6983 || r.sw == 0x6984 {
            s.set_tvr(TVR_PIN_TRY_LIMIT);
            return Ok(RESULT_FAILED);
        }
        return Err(KernelError::Card(r.sw)); // VERIFY failed
    }
}

/// Builds VERIFY with an enciphered PIN block. Ok(None) = key or challenge unavailable.
fn enciphered_verify(s: &mut Session, pin_block: &[u8; 8]) -> KResult<Option<Vec<u8>>> {
    let key = if let Some(cert) = s.get(0x9F2D).map(|c| c.to_vec()) {
        let k = retrieve_issuer_pk(s).and_then(|issuer| {
            let exp = s.get(0x9F2E).unwrap_or(&[0x03]).to_vec();
            let pan = s.get(0x5A).unwrap_or(&[]).to_vec();
            oda::recover_icc_pk(&issuer, &cert, s.get(0x9F2F), &exp, &[], &pan, &s.txn.date)
        });
        match k {
            Ok(k) => k,
            Err(_) => return Ok(None),
        }
    } else {
        match retrieve_icc_pk(s) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        }
    };
    let r = s.exchange(&apdu::get_challenge())?;
    if !r.ok() || r.data.len() != 8 || key.modulus.len() < 17 {
        return Ok(None);
    }
    let mut block = alloc::vec![0x7F];
    block.extend_from_slice(pin_block);
    block.extend_from_slice(&r.data);
    block.extend_from_slice(&s.env.random(key.modulus.len() - 17));
    match rsa_public(&key.modulus, &key.exponent, &block) {
        Some(enc) => Ok(Some(apdu::verify(&enc, 0x88))),
        None => Ok(None),
    }
}

// ------------------------------------------------------------------ GENERATE AC

fn cid_allowed(requested: u8, got: u8) -> bool {
    match got {
        apdu::AAC => true,
        apdu::ARQC => requested == apdu::ARQC || requested == apdu::TC,
        apdu::TC => requested == apdu::TC,
        _ => false,
    }
}

/// Ok(Some(cid)), Ok(None) when CDA verification failed.
fn generate_ac(s: &mut Session, ac: u8, cdol: &[u8], cda: bool, first: bool) -> KResult<Option<u8>> {
    if dol::contains(cdol, 0x98) {
        let tdol = match s.get(0x97) {
            Some(t) => t.to_vec(),
            None => {
                let t = s.aid.default_tdol.clone();
                if !t.is_empty() {
                    s.set_tvr(TVR_DEFAULT_TDOL);
                }
                t
            }
        };
        let data = s.build_dol(&tdol)?;
        s.db.set(0x98, &sha1(&data));
    }
    let data = s.build_dol(cdol)?;
    if first {
        s.cdol1_data = data.clone();
    }
    let use_cda = cda && ac != apdu::AAC && !s.tvr_bit(TVR_CDA_FAILED);
    let p1 = ac | if use_cda { apdu::CDA_REQUESTED } else { 0 };
    let r = s.exchange(&apdu::generate_ac(p1, &data))?;
    if !r.ok() {
        return Err(KernelError::Card(r.sw));
    }
    for t in [0x9F26, 0x9F4B, 0x9F27] {
        s.db.remove(t);
    }
    let children = parse_generate_ac(&r.data, &mut s.db)?;
    let cid_byte = s.get(0x9F27).and_then(|c| c.first().copied()).ok_or(KernelError::Card(0))?;
    let cid = cid_byte & 0xC0;
    if !cid_allowed(ac, cid) {
        return card_err(); // stronger cryptogram than requested
    }
    if use_cda && cid != apdu::AAC {
        let verified = retrieve_icc_pk(s).and_then(|icc| {
            let sdad = s.get(0x9F4B).ok_or(OdaError("SDAD missing"))?;
            let mut tx = s.pdol_data.clone();
            tx.extend_from_slice(&s.cdol1_data);
            if !first {
                tx.extend_from_slice(&data);
            }
            for (tag, enc) in &children {
                if *tag != 0x9F4B {
                    tx.extend_from_slice(enc);
                }
            }
            oda::verify_cda(&icc, sdad, s.get(0x9F37).unwrap_or(&[]), cid_byte, &tx)
        });
        match verified {
            Ok((acv, _)) => s.db.set(0x9F26, &acv),
            Err(_) => {
                s.set_tvr(TVR_CDA_FAILED);
                return Ok(None);
            }
        }
    } else if !s.db.has(0x9F26) {
        return card_err();
    }
    Ok(Some(cid))
}

// ------------------------------------------------------------------ scripts (Book 3 10.10)

fn run_scripts(s: &mut Session, scripts: &[u8], which: u32) -> KResult<Vec<u8>> {
    let mut out = Vec::new();
    if scripts.is_empty() {
        return Ok(out);
    }
    let templates = tlv::parse(scripts)?;
    for tmpl in templates.iter().filter(|t| t.tag == which) {
        let sid = tmpl.find(0x9F18).map(|t| t.value.to_vec());
        let (mut seq, mut result) = (0u8, 0x20u8);
        for c in tmpl.children().flatten() {
            if c.tag != 0x86 {
                continue;
            }
            seq = seq.saturating_add(1);
            let r = s.exchange(c.value)?;
            if !matches!(r.sw >> 8, 0x90 | 0x62 | 0x63) {
                result = 0x10 | seq.min(0x0F);
                s.set_tvr(if which == 0x71 { TVR_SCRIPT_FAILED_BEFORE } else { TVR_SCRIPT_FAILED_AFTER });
                break;
            }
        }
        s.set_tsi(TSI_SCRIPT);
        out.push(result);
        out.extend_from_slice(&sid.unwrap_or_else(|| alloc::vec![0; 4]));
    }
    Ok(out)
}

// ------------------------------------------------------------------ results

fn finish(s: &mut Session, status: Status, cvm: Cvm, scripts: Vec<u8>) -> ContactResult {
    s.sync();
    let msg = if status == Status::Approved { Message::Approved } else { Message::NotAuthorised };
    let mut o = Outcome::new(status, cvm, Some(msg));
    let mut tags: Vec<u32> = ONLINE_TAGS.to_vec();
    tags.extend_from_slice(&[0x8A, 0x9B]);
    o.data_record = s.db.subset(&tags);
    ContactResult { outcome: o, script_results: scripts, data: s.db.to_map() }
}
