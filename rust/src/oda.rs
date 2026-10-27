//! Offline Data Authentication: SDA, DDA, fDDA and CDA (EMV Book 2, sections 5 and 6).
//! RSA with SHA-1 only.

use alloc::string::String;
use alloc::vec::Vec;

use crate::capk::{Capk, CapkStore};
use crate::crypto::{rsa_public, sha1, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OdaError(pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

impl PublicKey {
    pub fn recover(&self, data: &[u8]) -> Result<Vec<u8>, OdaError> {
        if data.len() != self.modulus.len() {
            return Err(OdaError("certificate length differs from key modulus length"));
        }
        rsa_public(&self.modulus, &self.exponent, data).ok_or(OdaError("unusable public key"))
    }
}

fn check_frame(rec: &[u8], fmt: u8) -> Result<(), OdaError> {
    if rec.len() < 22 || rec[0] != 0x6A || rec[rec.len() - 1] != 0xBC {
        return Err(OdaError("recovered data header/trailer invalid"));
    }
    if rec[1] != fmt {
        return Err(OdaError("certificate format mismatch"));
    }
    Ok(())
}

fn check_hash(rec: &[u8], extra: &[&[u8]]) -> Result<(), OdaError> {
    let n = rec.len();
    let mut h = Sha1::new();
    h.update(&rec[1..n - 21]);
    for e in extra {
        h.update(e);
    }
    if h.finish()[..] != rec[n - 21..n - 1] {
        return Err(OdaError("hash result mismatch"));
    }
    Ok(())
}

fn bcd2(b: u8) -> u32 {
    (b >> 4) as u32 * 10 + (b & 0x0F) as u32
}

fn expired(mmyy: &[u8], today: &str) -> bool {
    let year = |yy: u32| if yy < 50 { 2000 + yy } else { 1900 + yy };
    let cert = year(bcd2(mmyy[1])) * 100 + bcd2(mmyy[0]);
    let t = today.as_bytes();
    let d = |i: usize| t.get(i).map_or(0, |c| c.wrapping_sub(b'0') as u32);
    let today = year(d(0) * 10 + d(1)) * 100 + d(2) * 10 + d(3);
    cert < today
}

/// Upper-case hex with trailing 'F' nibbles removed.
fn hex_strip_f(b: &[u8]) -> String {
    const HX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::new();
    for x in b {
        s.push(HX[(x >> 4) as usize] as char);
        s.push(HX[(x & 15) as usize] as char);
    }
    while s.ends_with('F') {
        s.pop();
    }
    s
}

fn pan_matches(prefix_cn: &[u8], pan: &[u8]) -> bool {
    let p = hex_strip_f(prefix_cn);
    p.len() >= 3 && hex_strip_f(pan).starts_with(&p)
}

pub fn recover_issuer_pk(
    capk: &Capk,
    cert: &[u8],
    remainder: Option<&[u8]>,
    exponent: &[u8],
    pan: &[u8],
    today: &str,
    store: Option<&CapkStore>,
) -> Result<PublicKey, OdaError> {
    let ca = PublicKey { modulus: capk.modulus.clone(), exponent: capk.exponent.clone() };
    let rec = ca.recover(cert)?;
    check_frame(&rec, 0x02)?;
    if rec.len() < 36 {
        return Err(OdaError("certificate too short"));
    }
    check_hash(&rec, &[remainder.unwrap_or(&[]), exponent])?;
    if !pan_matches(&rec[2..6], pan) {
        return Err(OdaError("issuer identifier does not match PAN"));
    }
    if expired(&rec[6..8], today) {
        return Err(OdaError("issuer certificate expired"));
    }
    if let Some(store) = store {
        if store.is_revoked(&capk.rid, capk.index, &rec[8..11]) {
            return Err(OdaError("issuer certificate revoked"));
        }
    }
    if rec[11] != 0x01 || rec[12] != 0x01 {
        return Err(OdaError("unsupported hash or PK algorithm"));
    }
    let ni = rec[13] as usize;
    let in_cert = rec.len() - 36;
    let mut modulus = rec[15..15 + ni.min(in_cert)].to_vec();
    if ni > in_cert {
        match remainder {
            Some(r) if r.len() == ni - in_cert => modulus.extend_from_slice(r),
            _ => return Err(OdaError("issuer PK remainder missing or wrong length")),
        }
    }
    Ok(PublicKey { modulus, exponent: exponent.to_vec() })
}

pub fn recover_icc_pk(
    issuer: &PublicKey,
    cert: &[u8],
    remainder: Option<&[u8]>,
    exponent: &[u8],
    static_data: &[u8],
    pan: &[u8],
    today: &str,
) -> Result<PublicKey, OdaError> {
    let rec = issuer.recover(cert)?;
    check_frame(&rec, 0x04)?;
    if rec.len() < 42 {
        return Err(OdaError("certificate too short"));
    }
    check_hash(&rec, &[remainder.unwrap_or(&[]), exponent, static_data])?;
    if hex_strip_f(&rec[2..12]) != hex_strip_f(pan) {
        return Err(OdaError("ICC certificate PAN mismatch"));
    }
    if expired(&rec[12..14], today) {
        return Err(OdaError("ICC certificate expired"));
    }
    if rec[17] != 0x01 || rec[18] != 0x01 {
        return Err(OdaError("unsupported hash or PK algorithm"));
    }
    let nic = rec[19] as usize;
    let in_cert = rec.len() - 42;
    let mut modulus = rec[21..21 + nic.min(in_cert)].to_vec();
    if nic > in_cert {
        match remainder {
            Some(r) if r.len() == nic - in_cert => modulus.extend_from_slice(r),
            _ => return Err(OdaError("ICC PK remainder missing or wrong length")),
        }
    }
    Ok(PublicKey { modulus, exponent: exponent.to_vec() })
}

/// Verify Signed Static Application Data; returns the Data Authentication Code (9F45).
pub fn verify_sda(issuer: &PublicKey, ssad: &[u8], static_data: &[u8]) -> Result<[u8; 2], OdaError> {
    let rec = issuer.recover(ssad)?;
    check_frame(&rec, 0x03)?;
    check_hash(&rec, &[static_data])?;
    Ok([rec[3], rec[4]])
}

/// DDA / fDDA / CDA signature check (format 05). Returns the ICC Dynamic Data.
pub fn verify_dynamic_signature(
    icc: &PublicKey,
    sdad: &[u8],
    terminal_dynamic_data: &[u8],
) -> Result<Vec<u8>, OdaError> {
    let rec = icc.recover(sdad)?;
    check_frame(&rec, 0x05)?;
    if rec[2] != 0x01 {
        return Err(OdaError("unsupported hash algorithm"));
    }
    let ldd = rec[3] as usize;
    if 4 + ldd > rec.len() - 21 {
        return Err(OdaError("ICC dynamic data length invalid"));
    }
    check_hash(&rec, &[terminal_dynamic_data])?;
    Ok(rec[4..4 + ldd].to_vec())
}

/// ICC Dynamic Number from ICC Dynamic Data (length-prefixed).
pub fn icc_dynamic_number(dd: &[u8]) -> &[u8] {
    let n = dd.first().copied().unwrap_or(0) as usize;
    dd.get(1..1 + n).unwrap_or(&[])
}

/// Verify a CDA signature; `tx_hash_input` = PDOL data ‖ CDOL data ‖ GENERATE AC TLVs minus 9F4B.
/// Returns (application cryptogram, ICC dynamic data).
pub fn verify_cda(
    icc: &PublicKey,
    sdad: &[u8],
    unpredictable_number: &[u8],
    cid: u8,
    tx_hash_input: &[u8],
) -> Result<([u8; 8], Vec<u8>), OdaError> {
    let dd = verify_dynamic_signature(icc, sdad, unpredictable_number)?;
    let n = *dd.first().ok_or(OdaError("CDA ICC dynamic data too short"))? as usize;
    if dd.len() < 1 + n + 1 + 8 + 20 {
        return Err(OdaError("CDA ICC dynamic data too short"));
    }
    if dd[1 + n] != cid {
        return Err(OdaError("CID in signature differs from CID in response"));
    }
    if sha1(tx_hash_input)[..] != dd[10 + n..30 + n] {
        return Err(OdaError("transaction data hash mismatch"));
    }
    let mut ac = [0u8; 8];
    ac.copy_from_slice(&dd[2 + n..10 + n]);
    Ok((ac, dd))
}
