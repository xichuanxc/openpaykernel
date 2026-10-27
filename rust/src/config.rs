//! Terminal, application (AID) and transaction parameters.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::capk::CapkStore;

#[derive(Debug, Clone)]
pub struct TerminalConfig {
    pub country_code: [u8; 2],
    pub terminal_type: u8,
    pub capabilities: [u8; 3],
    pub additional_capabilities: [u8; 5],
    pub terminal_id: Vec<u8>,
    pub ifd_serial: Vec<u8>,
    pub merchant_category_code: [u8; 2],
    pub merchant_id: Vec<u8>,
    pub merchant_name_location: Vec<u8>,
    /// Hot-listed PANs as upper-case digit strings without 'F' padding.
    pub exception_file: Vec<String>,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        TerminalConfig {
            country_code: [0x08, 0x40],
            terminal_type: 0x22,
            capabilities: [0xE0, 0xF8, 0xC8],
            additional_capabilities: [0x60, 0x00, 0xF0, 0xA0, 0x01],
            terminal_id: b"TERM0001".to_vec(),
            ifd_serial: b"00000001".to_vec(),
            merchant_category_code: [0x54, 0x11],
            merchant_id: b"MERCHANT0000001".to_vec(),
            merchant_name_location: b"OPEN L2 TEST SHOP".to_vec(),
            exception_file: Vec::new(),
        }
    }
}

impl TerminalConfig {
    pub fn online_capable(&self) -> bool {
        matches!(self.terminal_type & 0x0F, 1 | 2 | 4 | 5)
    }
    pub fn attended(&self) -> bool {
        self.terminal_type & 0x0F <= 3
    }
    pub fn tags(&self) -> Vec<(u32, Vec<u8>)> {
        alloc::vec![
            (0x9F1A, self.country_code.to_vec()),
            (0x9F35, alloc::vec![self.terminal_type]),
            (0x9F33, self.capabilities.to_vec()),
            (0x9F40, self.additional_capabilities.to_vec()),
            (0x9F1C, self.terminal_id.clone()),
            (0x9F1E, self.ifd_serial.clone()),
            (0x9F15, self.merchant_category_code.to_vec()),
            (0x9F16, self.merchant_id.clone()),
            (0x9F4E, self.merchant_name_location.clone()),
        ]
    }
}

#[derive(Debug, Clone)]
pub struct AidConfig {
    pub aid: Vec<u8>,
    /// 0 = derive from the RID.
    pub kernel_id: u32,
    pub partial_match: bool,
    pub app_version: [u8; 2],
    pub tac_default: [u8; 5],
    pub tac_denial: [u8; 5],
    pub tac_online: [u8; 5],
    pub floor_limit: u64,
    pub cl_transaction_limit: Option<u64>,
    pub cl_transaction_limit_cdcvm: Option<u64>,
    pub cvm_required_limit: Option<u64>,
    pub threshold: u64,
    pub target_percent: u8,
    pub max_target_percent: u8,
    pub default_ddol: Vec<u8>,
    pub default_tdol: Vec<u8>,
    pub ttq: [u8; 4],
    pub status_check: bool,
    pub zero_amount_allowed: bool,
    /// Kernel-specific TLVs (e.g. DF81xx for kernel 2), loaded into the transaction database.
    pub extra: BTreeMap<u32, Vec<u8>>,
}

impl AidConfig {
    pub fn new(aid: &[u8]) -> Self {
        AidConfig {
            aid: aid.to_vec(),
            kernel_id: 0,
            partial_match: true,
            app_version: [0x00, 0x02],
            tac_default: [0; 5],
            tac_denial: [0; 5],
            tac_online: [0; 5],
            floor_limit: 0,
            cl_transaction_limit: None,
            cl_transaction_limit_cdcvm: None,
            cvm_required_limit: None,
            threshold: 0,
            target_percent: 0,
            max_target_percent: 0,
            default_ddol: alloc::vec![0x9F, 0x37, 0x04],
            default_tdol: Vec::new(),
            ttq: [0x36, 0x00, 0x40, 0x00],
            status_check: false,
            zero_amount_allowed: true,
            extra: BTreeMap::new(),
        }
    }

    pub fn matches(&self, aid: &[u8]) -> bool {
        aid == self.aid.as_slice() || (self.partial_match && aid.starts_with(&self.aid))
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    /// Amount in minor units.
    pub amount: u64,
    pub amount_other: u64,
    pub currency_code: [u8; 2],
    pub currency_exponent: u8,
    /// 9C: 00 purchase, 01 cash, 09 cashback, 20 refund.
    pub txn_type: u8,
    /// YYMMDD
    pub date: String,
    /// HHMMSS
    pub time: String,
    pub sequence_counter: u32,
    pub force_online: bool,
}

impl Transaction {
    pub fn new(amount: u64) -> Self {
        Transaction {
            amount,
            amount_other: 0,
            currency_code: [0x08, 0x40],
            currency_exponent: 2,
            txn_type: 0x00,
            date: String::from("261027"),
            time: String::from("120000"),
            sequence_counter: 1,
            force_online: false,
        }
    }

    pub fn tags(&self) -> Vec<(u32, Vec<u8>)> {
        alloc::vec![
            (0x9F02, bcd(self.amount, 6)),
            (0x9F03, bcd(self.amount_other, 6)),
            (0x81, (self.amount as u32).to_be_bytes().to_vec()),
            (0x9F04, (self.amount_other as u32).to_be_bytes().to_vec()),
            (0x5F2A, self.currency_code.to_vec()),
            (0x5F36, alloc::vec![self.currency_exponent]),
            (0x9C, alloc::vec![self.txn_type]),
            (0x9A, hex_digits(&self.date)),
            (0x9F21, hex_digits(&self.time)),
            (0x9F41, bcd(self.sequence_counter as u64, 4)),
        ]
    }
}

/// Unsigned integer → BCD of `len` bytes.
pub fn bcd(mut n: u64, len: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; len];
    for i in (0..len).rev() {
        let lo = (n % 10) as u8;
        n /= 10;
        let hi = (n % 10) as u8;
        n /= 10;
        out[i] = (hi << 4) | lo;
    }
    out
}

/// BCD → integer (0 if not valid BCD).
pub fn bcd_to_int(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &x in b {
        if x >> 4 > 9 || x & 0x0F > 9 {
            return 0;
        }
        v = v * 100 + (x >> 4) as u64 * 10 + (x & 0x0F) as u64;
    }
    v
}

fn hex_digits(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| ((c[0].wrapping_sub(b'0')) << 4) | c.get(1).map_or(0, |d| d.wrapping_sub(b'0')))
        .collect()
}

/// `byte`/`bit` are 1-based as in the EMV books.
pub fn bit(data: Option<&[u8]>, byte: usize, b: u8) -> bool {
    data.and_then(|d| d.get(byte - 1)).is_some_and(|x| x & (1 << (b - 1)) != 0)
}

pub type RngFn = Box<dyn FnMut(&mut [u8])>;

/// Everything a kernel needs besides the card: configuration, keys and the RNG.
pub struct Environment {
    pub terminal: TerminalConfig,
    pub aids: Vec<AidConfig>,
    pub capks: CapkStore,
    rng: RefCell<RngFn>,
}

impl Environment {
    /// `rng` fills a buffer with unpredictable bytes (use a secure source in a real terminal).
    pub fn new(terminal: TerminalConfig, aids: Vec<AidConfig>, capks: CapkStore, rng: RngFn) -> Self {
        Environment { terminal, aids, capks, rng: RefCell::new(rng) }
    }

    pub fn random(&self, n: usize) -> Vec<u8> {
        let mut v = alloc::vec![0u8; n];
        (self.rng.borrow_mut())(&mut v);
        v
    }
}
