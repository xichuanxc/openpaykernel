//! Contactless Entry Point (EMV Contactless Book B).

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::apdu::{self, Channel, Reader, TransmissionError};
use crate::config::{AidConfig, Environment, Transaction};
use crate::outcome::{L2Error, Message, Outcome, Status};
use crate::tlv;

pub const PPSE: &[u8] = b"2PAY.SYS.DDF01";

/// Kernels whose PDOL carries the Terminal Transaction Qualifiers (9F66) built at pre-processing.
pub const TTQ_KERNELS: &[u32] = &[3, 6, 7];

pub fn default_kernel_id(aid: &[u8]) -> u32 {
    match aid.get(..5) {
        Some([0xA0, 0x00, 0x00, 0x00, 0x04]) => 2,
        Some([0xA0, 0x00, 0x00, 0x00, 0x03]) => 3,
        Some([0xA0, 0x00, 0x00, 0x00, 0x25]) => 4,
        Some([0xA0, 0x00, 0x00, 0x00, 0x65]) => 5,
        Some([0xA0, 0x00, 0x00, 0x01, 0x52]) => 6,
        Some([0xA0, 0x00, 0x00, 0x03, 0x33]) => 7,
        _ => 0,
    }
}

/// Book B 3.3.2.5: map Kernel Identifier (9F2A) to a kernel ID.
pub fn requested_kernel_id(kid: Option<&[u8]>, aid: &[u8]) -> u32 {
    match kid {
        None | Some([]) | Some([0, ..]) => default_kernel_id(aid),
        Some(k) if k[0] >> 6 <= 1 => (k[0] & 0x3F) as u32,
        Some(k) => k.iter().take(3).fold(0u32, |a, &b| (a << 8) | b as u32),
    }
}

/// Book B 3.1.1 pre-processing indicators, kept per AID/kernel combination.
#[derive(Debug, Clone, Default)]
pub struct Preprocessing {
    pub status_check: bool,
    pub not_allowed: bool,
    pub zero_amount: bool,
    pub cvm_required_limit_exceeded: bool,
    pub floor_limit_exceeded: bool,
    pub cl_limit_exceeded: bool,
    pub ttq: Option<[u8; 4]>,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub adf_name: Vec<u8>,
    pub kernel_id: u32,
    pub priority: u8,
    pub label: Vec<u8>,
    /// Index into `Environment::aids`.
    pub aid_index: usize,
    order: usize,
}

/// What a contactless kernel receives after final selection.
pub struct KernelContext<'a, 'r> {
    pub env: &'a Environment,
    pub txn: &'a Transaction,
    pub chan: &'a mut Channel<'r>,
    pub candidate: &'a Candidate,
    pub aid: &'a AidConfig,
    pub pre: &'a Preprocessing,
    pub fci: &'a [u8],
    pub sw: u16,
}

/// A contactless kernel plug-in (Kernel 2, Kernel 3, ...).
pub trait ContactlessKernel {
    fn kernel_id(&self) -> u32;
    fn start(&self, ctx: &mut KernelContext<'_, '_>) -> Result<Outcome, TransmissionError>;
}

pub struct EntryPoint {
    pub env: Environment,
    kernels: Vec<Box<dyn ContactlessKernel>>,
    combos: Vec<(usize, u32, Preprocessing)>,
}

impl EntryPoint {
    pub fn new(env: Environment, kernels: Vec<Box<dyn ContactlessKernel>>) -> Self {
        EntryPoint { env, kernels, combos: Vec::new() }
    }

    fn kernel(&self, id: u32) -> Option<&dyn ContactlessKernel> {
        self.kernels.iter().find(|k| k.kernel_id() == id).map(|k| k.as_ref())
    }

    /// Start A: pre-processing. Returns an outcome if contactless is not allowed at all.
    pub fn preprocess(&mut self, txn: &Transaction) -> Option<Outcome> {
        self.combos.clear();
        let amount = txn.amount;
        let one_unit = 10u64.pow(txn.currency_exponent as u32);
        for (i, cfg) in self.env.aids.iter().enumerate() {
            let kid = if cfg.kernel_id != 0 { cfg.kernel_id } else { default_kernel_id(&cfg.aid) };
            if !self.kernels.iter().any(|k| k.kernel_id() == kid) {
                continue;
            }
            let mut p = Preprocessing::default();
            if cfg.status_check && amount == one_unit {
                p.status_check = true;
            }
            if amount == 0 {
                if cfg.zero_amount_allowed {
                    p.zero_amount = true;
                } else {
                    p.not_allowed = true;
                }
            }
            if let Some(limit) = cfg.cl_transaction_limit {
                if amount >= limit {
                    p.cl_limit_exceeded = true;
                    if cfg.cl_transaction_limit_cdcvm.is_none() {
                        p.not_allowed = true;
                    }
                }
            }
            if amount > cfg.floor_limit {
                p.floor_limit_exceeded = true;
            }
            if let Some(limit) = cfg.cvm_required_limit {
                if amount >= limit {
                    p.cvm_required_limit_exceeded = true;
                }
            }
            if TTQ_KERNELS.contains(&kid) {
                let mut ttq = cfg.ttq;
                ttq[1] &= 0x3F;
                if p.status_check || p.zero_amount || p.floor_limit_exceeded {
                    ttq[1] |= 0x80;
                }
                if p.cvm_required_limit_exceeded {
                    ttq[1] |= 0x40;
                }
                p.ttq = Some(ttq);
            }
            self.combos.push((i, kid, p));
        }
        if self.combos.is_empty() || self.combos.iter().all(|c| c.2.not_allowed) {
            return Some(Outcome::try_another_interface());
        }
        None
    }

    /// Start C: SELECT PPSE and build the sorted candidate list.
    pub fn build_candidates(&self, chan: &mut Channel) -> Result<Vec<Candidate>, Outcome> {
        let r = chan
            .exchange(&apdu::select(PPSE, true))
            .map_err(|_| Outcome::try_again_l1(Some(Message::PresentCardAgain)))?;
        if !r.ok() {
            return Err(Outcome::end_application(L2Error::NoPpse, r.sw, Some(Message::InsertSwipeOrTryAnother)));
        }
        let fault = || Outcome::end_application(L2Error::PpseFault, r.sw, Some(Message::InsertSwipeOrTryAnother));
        let nodes = tlv::parse(&r.data).map_err(|_| fault())?;
        let bf0c = nodes.first().filter(|n| n.tag == 0x6F).and_then(|t| t.find(0xBF0C)).ok_or_else(fault)?;
        let mut cands = Vec::new();
        for entry in bf0c.children().flatten() {
            if entry.tag != 0x61 {
                continue;
            }
            let adf = match entry.find(0x4F) {
                Some(a) if (5..=16).contains(&a.value.len()) => a.value,
                _ => continue,
            };
            let kid = requested_kernel_id(entry.find(0x9F2A).map(|t| t.value), adf);
            let prio = entry.find(0x87).and_then(|p| p.value.first().copied()).map_or(0, |p| p & 0x0F);
            let label = entry.find(0x50).map_or(Vec::new(), |l| l.value.to_vec());
            for (aid_index, combo_kid, pre) in &self.combos {
                if pre.not_allowed || *combo_kid != kid || !self.env.aids[*aid_index].matches(adf) {
                    continue;
                }
                let order = cands.len();
                cands.push(Candidate {
                    adf_name: adf.to_vec(),
                    kernel_id: kid,
                    priority: prio,
                    label,
                    aid_index: *aid_index,
                    order,
                });
                break;
            }
        }
        // lower value = higher priority; 0 (none) last; ties keep PPSE order
        cands.sort_by_key(|c| (c.priority == 0, c.priority, c.order));
        if cands.is_empty() {
            return Err(Outcome::end_application(
                L2Error::EmptyCandidateList,
                0,
                Some(Message::InsertSwipeOrTryAnother),
            ));
        }
        Ok(cands)
    }

    /// Run a complete contactless transaction. The APDU log is returned in `log` if given.
    pub fn process(
        &mut self,
        reader: &mut dyn Reader,
        txn: &Transaction,
        log: Option<&mut Vec<(Vec<u8>, Vec<u8>)>>,
    ) -> Outcome {
        if let Some(out) = self.preprocess(txn) {
            return out;
        }
        let mut chan = Channel::new(reader);
        let out = self.select_and_run(&mut chan, txn);
        if let Some(l) = log {
            l.append(&mut chan.log);
        }
        out
    }

    fn select_and_run(&self, chan: &mut Channel, txn: &Transaction) -> Outcome {
        let cands = match self.build_candidates(chan) {
            Ok(c) => c,
            Err(o) => return o,
        };
        for cand in &cands {
            let r = match chan.exchange(&apdu::select(&cand.adf_name, true)) {
                Ok(r) => r,
                Err(_) => return Outcome::try_again_l1(None),
            };
            if !r.ok() {
                continue;
            }
            let pre = &self.combos.iter().find(|c| c.0 == cand.aid_index).expect("combo for candidate").2;
            let kernel = match self.kernel(cand.kernel_id) {
                Some(k) => k,
                None => continue,
            };
            let mut ctx = KernelContext {
                env: &self.env,
                txn,
                chan: &mut *chan,
                candidate: cand,
                aid: &self.env.aids[cand.aid_index],
                pre,
                fci: &r.data,
                sw: r.sw,
            };
            match kernel.start(&mut ctx) {
                Err(_) => return Outcome::try_again_l1(Some(Message::PresentCardAgain)),
                Ok(o) if o.status == Status::SelectNext => continue,
                Ok(o) => return o,
            }
        }
        Outcome::end_application(L2Error::EmptyCandidateList, 0, Some(Message::InsertSwipeOrTryAnother))
    }
}
