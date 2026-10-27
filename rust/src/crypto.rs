//! SHA-1 (FIPS 180-4) and the RSA public-key operation (Montgomery multiplication).
//!
//! An EMV terminal only performs public-key operations, so constant-time code is not needed.

use alloc::vec;
use alloc::vec::Vec;

pub struct Sha1 {
    h: [u32; 5],
    total: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 { h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0], total: 0, buf: [0; 64], buf_len: 0 }
    }

    fn block(h: &mut [u32; 5], p: &[u8]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([p[4 * i], p[4 * i + 1], p[4 * i + 2], p[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        while !data.is_empty() {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::block(&mut self.h, &self.buf);
                self.buf_len = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 20] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        for (i, v) in self.h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut s = Sha1::new();
    s.update(data);
    s.finish()
}

// ------------------------------------------------------------------ bignum (little-endian u32 limbs)

fn from_be(b: &[u8], k: usize) -> Vec<u32> {
    let mut r = vec![0u32; k];
    for (i, &byte) in b.iter().rev().enumerate() {
        r[i / 4] |= (byte as u32) << (8 * (i % 4));
    }
    r
}

fn to_be(a: &[u32], len: usize) -> Vec<u8> {
    (0..len).rev().map(|i| (a[i / 4] >> (8 * (i % 4))) as u8).collect()
}

fn cmp(a: &[u32], b: &[u32]) -> core::cmp::Ordering {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    core::cmp::Ordering::Equal
}

fn sub_in_place(a: &mut [u32], b: &[u32]) {
    let mut borrow = 0i64;
    for i in 0..a.len() {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        a[i] = d as u32;
        borrow = (d >> 63) & 1;
    }
}

/// a * b * R^-1 mod n (CIOS)
fn mont_mul(a: &[u32], b: &[u32], n: &[u32], n0inv: u32) -> Vec<u32> {
    let k = n.len();
    let mut t = vec![0u32; k + 2];
    for &bi in &b[..k] {
        let mut c = 0u64;
        for j in 0..k {
            let s = t[j] as u64 + a[j] as u64 * bi as u64 + c;
            t[j] = s as u32;
            c = s >> 32;
        }
        let s = t[k] as u64 + c;
        t[k] = s as u32;
        t[k + 1] = (s >> 32) as u32;
        let m = t[0].wrapping_mul(n0inv);
        let s = t[0] as u64 + m as u64 * n[0] as u64;
        let mut c = s >> 32;
        for j in 1..k {
            let s = t[j] as u64 + m as u64 * n[j] as u64 + c;
            t[j - 1] = s as u32;
            c = s >> 32;
        }
        let s = t[k] as u64 + c;
        t[k - 1] = s as u32;
        t[k] = t[k + 1].wrapping_add((s >> 32) as u32);
    }
    let overflow = t[k] != 0;
    let mut r: Vec<u32> = t[..k].to_vec();
    if overflow || cmp(&r, n) != core::cmp::Ordering::Less {
        sub_in_place(&mut r, n);
    }
    r
}

/// `input^exponent mod modulus`, all big-endian, output has the modulus length.
/// Returns None for an even/empty modulus, an exponent over 4 bytes, or a length mismatch.
pub fn rsa_public(modulus: &[u8], exponent: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    let len = modulus.len();
    if len == 0 || modulus[len - 1] & 1 == 0 || exponent.is_empty() || exponent.len() > 4 || input.len() != len {
        return None;
    }
    let k = len.div_ceil(4);
    let n = from_be(modulus, k);
    let mut a = from_be(input, k);
    let mut guard = 0;
    while cmp(&a, &n) != core::cmp::Ordering::Less && guard < 300 {
        sub_in_place(&mut a, &n);
        guard += 1;
    }
    let mut inv: u32 = 1;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(n[0].wrapping_mul(inv)));
    }
    let n0inv = inv.wrapping_neg();
    // R^2 mod n by doubling 1, 64*k times
    let mut rr = vec![0u32; k];
    rr[0] = 1;
    for _ in 0..64 * k {
        let mut carry = 0u32;
        for w in rr.iter_mut() {
            let nc = *w >> 31;
            *w = (*w << 1) | carry;
            carry = nc;
        }
        if carry != 0 || cmp(&rr, &n) != core::cmp::Ordering::Less {
            sub_in_place(&mut rr, &n);
        }
    }
    let mut one = vec![0u32; k];
    one[0] = 1;
    let am = mont_mul(&a, &rr, &n, n0inv);
    let mut xm = mont_mul(&one, &rr, &n, n0inv);
    let e = exponent.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
    for i in (0..32 - e.leading_zeros()).rev() {
        xm = mont_mul(&xm, &xm, &n, n0inv);
        if (e >> i) & 1 == 1 {
            xm = mont_mul(&xm, &am, &n, n0inv);
        }
    }
    let x = mont_mul(&xm, &one, &n, n0inv);
    Some(to_be(&x, len))
}
