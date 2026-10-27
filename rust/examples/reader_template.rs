//! Minimal template: connect OpenPayKernel to YOUR reader hardware.
//!
//! The kernel needs exactly one hardware function, `Reader::transmit`:
//!   * input:  a complete command APDU (`CLA INS P1 P2 [Lc data] [Le]`)
//!   * output: response data followed by `SW1 SW2`
//!   * error:  `TransmissionError` on a Level-1 error (no card, card removed, timeout)
//!
//! GET RESPONSE (61xx), wrong Le (6Cxx) and everything above are handled by the kernel.
//! Card activation (contact power-up / contactless polling + anticollision) is the reader's
//! job and must happen before `process()` is called.
//!
//! Run: `cargo run --example reader_template [contact]`
//!
//! For a PC/SC reader, wrap the `pcsc` crate (`card.transmit(capdu, &mut buf)`) in the same way.
//! STUDY USE ONLY - see the Disclaimer in README.md.

use std::collections::BTreeMap;

use openpaykernel::apdu::{Reader, TransmissionError};
use openpaykernel::{
    AidConfig, AmexKernel, AppCandidate, CapkStore, ContactHost, ContactKernel, DiscoverKernel, EntryPoint,
    Environment, MastercardKernel, OnlineResponse, TerminalConfig, Transaction, UnionPayKernel, VisaKernel,
};

// ---------------------------------------------------------------- your hardware goes here
struct MyDevice {
    // e.g. a serial port, a USB handle, an NFC controller context
}

impl MyDevice {
    /// Stand-in for your vendor SDK. It answers "file not found" (6A82) to everything, so
    /// this template runs without hardware and shows how the kernel reports the result.
    fn vendor_sdk_exchange(&mut self, _cmd: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(vec![0x6A, 0x82])
    }
}

impl Reader for MyDevice {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8>, TransmissionError> {
        match self.vendor_sdk_exchange(capdu) {
            Ok(rsp) if rsp.len() >= 2 => Ok(rsp), // data + SW1 SW2
            _ => Err(TransmissionError),          // Level-1 error
        }
    }
}
// -----------------------------------------------------------------------------------------

/// Prints every APDU going through any Reader.
struct Tracing<R: Reader>(R);

impl<R: Reader> Reader for Tracing<R> {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8>, TransmissionError> {
        println!("  > {}", hex(capdu));
        let r = self.0.transmit(capdu);
        match &r {
            Ok(rsp) => println!("  < {}", hex(rsp)),
            Err(_) => println!("  < (level-1 error)"),
        }
        r
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

struct ConsoleHost;

impl ContactHost for ConsoleHost {
    fn choose_application(&mut self, _c: &[AppCandidate]) -> Option<usize> {
        Some(0)
    }
    fn enter_pin(&mut self, _online: bool, _tries: Option<u8>) -> Option<String> {
        None // bypass; a real terminal uses a certified PIN pad
    }
    fn go_online(&mut self, _data: &BTreeMap<u32, Vec<u8>>) -> Option<OnlineResponse> {
        None // unable to go online
    }
}

fn environment() -> Environment {
    let mut visa = AidConfig::new(&[0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]);
    visa.kernel_id = 3;
    visa.floor_limit = 10000;
    visa.cl_transaction_limit = Some(50000);
    visa.cvm_required_limit = Some(3000);
    let mut mc = AidConfig::new(&[0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10]);
    mc.kernel_id = 2;
    mc.floor_limit = 10000;
    let mut disc = AidConfig::new(&[0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10]);
    disc.kernel_id = 6;
    disc.floor_limit = 10000;
    disc.cl_transaction_limit = Some(50000);
    disc.cvm_required_limit = Some(3000);
    let mut amex = AidConfig::new(&[0xA0, 0x00, 0x00, 0x00, 0x25, 0x01]);
    amex.kernel_id = 4;
    amex.floor_limit = 10000;
    amex.cl_transaction_limit = Some(50000);
    amex.cvm_required_limit = Some(3000);
    amex.extra.insert(0x9F6E, vec![0xD8, 0xE0, 0x00, 0x03]); // Enhanced Contactless Reader Capabilities
    let mut jcb = AidConfig::new(&[0xA0, 0x00, 0x00, 0x00, 0x65, 0x10, 0x10]);
    jcb.kernel_id = 5;
    jcb.floor_limit = 10000;
    jcb.cl_transaction_limit = Some(50000);
    jcb.cvm_required_limit = Some(3000);
    jcb.extra.insert(0x9F53, vec![0x72, 0x00, 0x00]); // Terminal Interchange Profile
    let mut upi = AidConfig::new(&[0xA0, 0x00, 0x00, 0x03, 0x33, 0x01, 0x01]); // partial match: 0101xx
    upi.kernel_id = 7;
    upi.floor_limit = 10000;
    upi.cl_transaction_limit = Some(50000);
    upi.cvm_required_limit = Some(3000);
    // Use a secure RNG on a real terminal; this template uses the clock for simplicity.
    let mut seed =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |d| d.as_nanos() as u64);
    let rng = Box::new(move |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = seed as u8;
        }
    });
    Environment::new(TerminalConfig::default(), vec![visa, mc, upi, disc, amex, jcb], CapkStore::new(), rng)
}

fn main() {
    let contact = std::env::args().nth(1).as_deref() == Some("contact");
    let mut reader = Tracing(MyDevice {});
    let txn = Transaction::new(100); // 1.00
    println!("{} transaction, APDU trace:", if contact { "contact" } else { "contactless" });
    let (outcome, data) = if contact {
        let r = ContactKernel::new(environment(), ConsoleHost).process(&mut reader, &txn, None);
        (r.outcome, r.data)
    } else {
        let mut ep = EntryPoint::new(
            environment(),
            vec![
                Box::new(VisaKernel),
                Box::new(MastercardKernel),
                Box::new(UnionPayKernel),
                Box::new(DiscoverKernel),
                Box::new(AmexKernel),
            ],
        );
        let o = ep.process(&mut reader, &txn, None);
        let d = o.data_record.clone();
        (o, d)
    };
    println!("\noutcome: {:?}  CVM: {:?}  error: {:?}", outcome.status, outcome.cvm, outcome.error);
    for tag in [0x95u32, 0x9F34, 0x9F27, 0x9F26] {
        if let Some(v) = data.get(&tag) {
            println!("  {tag:>6X} {}", hex(v));
        }
    }
}
