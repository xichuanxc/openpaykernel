//! Certification Authority Public Keys (EMV Book 2, section 11.2.2) and the revocation list.

use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::Sha1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capk {
    pub rid: [u8; 5],
    pub index: u8,
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
    /// Expiry as YYMMDD.
    pub expiry: String,
    pub checksum: Option<[u8; 20]>,
}

impl Capk {
    pub fn new(rid: [u8; 5], index: u8, modulus: Vec<u8>, exponent: Vec<u8>, expiry: &str) -> Self {
        Capk { rid, index, modulus, exponent, expiry: String::from(expiry), checksum: None }
    }

    pub fn computed_checksum(&self) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(&self.rid);
        h.update(&[self.index]);
        h.update(&self.modulus);
        h.update(&self.exponent);
        h.finish()
    }

    pub fn verify(&self) -> bool {
        self.checksum.map_or(true, |c| c == self.computed_checksum())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumMismatch;

#[derive(Debug, Clone, Default)]
pub struct CapkStore {
    pub keys: Vec<Capk>,
    /// (RID, index, issuer certificate serial number)
    pub revoked: Vec<([u8; 5], u8, [u8; 3])>,
}

impl CapkStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, key: Capk) -> Result<(), ChecksumMismatch> {
        if !key.verify() {
            return Err(ChecksumMismatch);
        }
        self.keys.retain(|k| !(k.rid == key.rid && k.index == key.index));
        self.keys.push(key);
        Ok(())
    }

    /// `today` is YYMMDD. An expired key is treated as absent.
    pub fn find(&self, rid: &[u8], index: u8, today: Option<&str>) -> Option<&Capk> {
        let k = self.keys.iter().find(|k| k.rid[..] == *rid && k.index == index)?;
        match today {
            Some(t) if yymmdd_key(&k.expiry) < yymmdd_key(t) => None,
            _ => Some(k),
        }
    }

    pub fn revoke(&mut self, rid: [u8; 5], index: u8, serial: [u8; 3]) {
        self.revoked.push((rid, index, serial));
    }

    pub fn is_revoked(&self, rid: &[u8; 5], index: u8, serial: &[u8]) -> bool {
        self.revoked.iter().any(|(r, i, s)| r == rid && *i == index && s[..] == *serial)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// YYMMDD → sortable YYYYMMDD (YY < 50 → 20YY).
pub(crate) fn yymmdd_key(d: &str) -> u32 {
    let digits: Vec<u32> = d.bytes().take(6).map(|b| b.wrapping_sub(b'0') as u32).collect();
    if digits.len() != 6 || digits.iter().any(|&x| x > 9) {
        return 0;
    }
    let yy = digits[0] * 10 + digits[1];
    let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
    year * 10000 + (digits[2] * 10 + digits[3]) * 100 + digits[4] * 10 + digits[5]
}
