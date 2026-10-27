//! Replays every shared conformance vector: the Rust kernels must send byte-identical
//! command APDUs and reach the same outcome as the Python reference (and the C library).

mod common;

use std::collections::BTreeMap;

use common::*;
use openpaykernel::{ContactKernel, EntryPoint, MastercardKernel, Outcome, VisaKernel};

fn run(v: &common::Vector, reader: &mut Replay) -> (Outcome, BTreeMap<u32, Vec<u8>>) {
    let env = environment(v);
    if v.contact {
        let mut k = ContactKernel::new(env, ScriptedHost::new(v.host.clone()));
        let r = k.process(reader, &v.txn, None);
        (r.outcome, r.data)
    } else {
        let mut ep = EntryPoint::new(env, vec![Box::new(VisaKernel), Box::new(MastercardKernel)]);
        let o = ep.process(reader, &v.txn, None);
        let d = o.data_record.clone();
        (o, d)
    }
}

#[test]
fn all_conformance_vectors() {
    let vectors = load_all();
    assert!(vectors.len() >= 19, "expected the shared vectors, found {}", vectors.len());
    let mut failures = Vec::new();
    for v in &vectors {
        let mut reader = Replay::new(v.apdus.clone());
        let (out, data) = run(v, &mut reader);
        let mut errs = Vec::new();
        if let Some(m) = &reader.mismatch {
            errs.push(m.clone());
        }
        if reader.pos != v.apdus.len() {
            errs.push(format!("only {} of {} APDUs exchanged", reader.pos, v.apdus.len()));
        }
        if out.status as u8 != v.status || out.cvm as u8 != v.cvm {
            errs.push(format!("outcome {:?}/{:?}, expected status {}/cvm {}", out.status, out.cvm, v.status, v.cvm));
        }
        for (tag, want) in &v.tags {
            if data.get(tag) != Some(want) {
                errs.push(format!("tag {tag:X}: expected {}, got {:?}", hex(want), data.get(tag).map(|d| hex(d))));
            }
        }
        println!("{:<32} {}", v.name, if errs.is_empty() { "ok" } else { "FAIL" });
        if !errs.is_empty() {
            failures.push(format!("[{}]\n  {}", v.name, errs.join("\n  ")));
        }
    }
    assert!(failures.is_empty(), "{} vector(s) failed:\n{}", failures.len(), failures.join("\n"));
}

/// Corrupted card responses must never panic (the Rust equivalent of a crash).
#[test]
fn fuzz_corrupted_responses_never_panic() {
    let iterations: u32 = std::env::var("OPK_FUZZ").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut apdus = 0usize;
    for v in load_all() {
        for i in 0..iterations {
            let mut reader = Replay::new(v.apdus.clone());
            reader.fuzz = Some(i.wrapping_mul(2654435761));
            let (out, _) = run(&v, &mut reader);
            apdus += reader.pos;
            *seen.entry(format!("{:?}", out.status)).or_default() += 1;
        }
    }
    println!("fuzz outcomes: {seen:?}, {apdus} APDUs");
    // the corruption must still let many transactions run deep enough to reach real decisions
    for s in ["Approved", "Declined", "OnlineRequest", "EndApplication"] {
        assert!(seen.get(s).copied().unwrap_or(0) > 0, "fuzzing never reached {s}: {seen:?}");
    }
}
