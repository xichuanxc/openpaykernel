//! BER-TLV encoding as used by EMV (EMV Book 3, Annex B) and the per-transaction TLV database.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::tags;

/// Malformed BER-TLV data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvError;

/// One decoded TLV object, borrowing from the input buffer.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub value: &'a [u8],
    /// The complete encoded object (tag + length + value).
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn constructed(&self) -> bool {
        is_constructed(self.tag)
    }

    /// Depth-first search of this object's subtree (excluding itself).
    pub fn find(&self, tag: u32) -> Option<Tlv<'a>> {
        if self.constructed() {
            find(self.value, tag)
        } else {
            None
        }
    }

    pub fn children(&self) -> Iter<'a> {
        Iter { buf: if self.constructed() { self.value } else { &[] }, pos: 0 }
    }
}

fn first_byte(mut tag: u32) -> u32 {
    while tag > 0xFF {
        tag >>= 8;
    }
    tag
}

pub fn is_constructed(tag: u32) -> bool {
    first_byte(tag) & 0x20 != 0
}

pub fn parse_tag(buf: &[u8], pos: &mut usize) -> Result<u32, TlvError> {
    let first = *buf.get(*pos).ok_or(TlvError)?;
    *pos += 1;
    let mut tag = first as u32;
    if first & 0x1F == 0x1F {
        let mut n = 0;
        loop {
            let b = *buf.get(*pos).ok_or(TlvError)?;
            *pos += 1;
            n += 1;
            if n > 3 {
                return Err(TlvError);
            }
            tag = (tag << 8) | b as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    Ok(tag)
}

pub fn parse_length(buf: &[u8], pos: &mut usize) -> Result<usize, TlvError> {
    let b = *buf.get(*pos).ok_or(TlvError)?;
    *pos += 1;
    if b < 0x80 {
        return Ok(b as usize);
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || n > 3 || *pos + n > buf.len() {
        return Err(TlvError);
    }
    let mut v = 0usize;
    for &x in &buf[*pos..*pos + n] {
        v = (v << 8) | x as usize;
    }
    *pos += n;
    Ok(v)
}

/// Iterator over the top-level objects of a buffer; padding bytes 00/FF are skipped.
pub struct Iter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Iter { buf, pos: 0 }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<Tlv<'a>, TlvError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.buf.len() && (self.buf[self.pos] == 0x00 || self.buf[self.pos] == 0xFF) {
            self.pos += 1;
        }
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        let r = (|| {
            let tag = parse_tag(self.buf, &mut self.pos)?;
            let len = parse_length(self.buf, &mut self.pos)?;
            let end = self.pos.checked_add(len).filter(|&e| e <= self.buf.len()).ok_or(TlvError)?;
            let value = &self.buf[self.pos..end];
            self.pos = end;
            Ok(Tlv { tag, value, raw: &self.buf[start..end] })
        })();
        if r.is_err() {
            self.pos = self.buf.len(); // stop after an error
        }
        Some(r)
    }
}

/// Parse the top-level objects of a buffer, validating nested templates too.
pub fn parse(buf: &[u8]) -> Result<Vec<Tlv<'_>>, TlvError> {
    check(buf)?;
    Iter::new(buf).collect()
}

/// Validate a whole buffer, recursing into constructed objects.
pub fn check(buf: &[u8]) -> Result<(), TlvError> {
    for t in Iter::new(buf) {
        let t = t?;
        if t.constructed() {
            check(t.value)?;
        }
    }
    Ok(())
}

/// Depth-first search for `tag` (returns None on malformed data).
pub fn find(buf: &[u8], tag: u32) -> Option<Tlv<'_>> {
    for t in Iter::new(buf) {
        let t = t.ok()?;
        if t.tag == tag {
            return Some(t);
        }
        if t.constructed() {
            if let Some(hit) = find(t.value, tag) {
                return Some(hit);
            }
        }
    }
    None
}

/// Visit every primitive object of a tree, in order.
pub fn for_each_primitive<'a>(nodes: &[Tlv<'a>], f: &mut dyn FnMut(&Tlv<'a>)) -> Result<(), TlvError> {
    for n in nodes {
        if n.constructed() {
            let kids: Result<Vec<_>, _> = Iter::new(n.value).collect();
            for_each_primitive(&kids?, f)?;
        } else {
            f(n);
        }
    }
    Ok(())
}

pub fn tag_bytes(tag: u32, out: &mut Vec<u8>) {
    if tag > 0xFF_FFFF {
        out.push((tag >> 24) as u8);
    }
    if tag > 0xFFFF {
        out.push((tag >> 16) as u8);
    }
    if tag > 0xFF {
        out.push((tag >> 8) as u8);
    }
    out.push(tag as u8);
}

pub fn encode_into(tag: u32, value: &[u8], out: &mut Vec<u8>) {
    tag_bytes(tag, out);
    let n = value.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xFF {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(value);
}

pub fn encode(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(value.len() + 5);
    encode_into(tag, value, &mut v);
    v
}

/// Parse a list of tags without lengths (e.g. tag 9F4A, SDA Tag List).
pub fn parse_tag_list(buf: &[u8]) -> Result<Vec<u32>, TlvError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        out.push(parse_tag(buf, &mut pos)?);
    }
    Ok(out)
}

/// Flat tag → value store for one transaction.
#[derive(Debug, Clone, Default)]
pub struct TlvDb {
    map: BTreeMap<u32, Vec<u8>>,
}

impl TlvDb {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get(&self, tag: u32) -> Option<&[u8]> {
        self.map.get(&tag).map(|v| v.as_slice())
    }
    pub fn has(&self, tag: u32) -> bool {
        self.map.contains_key(&tag)
    }
    pub fn set(&mut self, tag: u32, value: &[u8]) {
        self.map.insert(tag, value.to_vec());
    }
    pub fn remove(&mut self, tag: u32) {
        self.map.remove(&tag);
    }
    pub fn iter(&self) -> impl Iterator<Item = (&u32, &Vec<u8>)> {
        self.map.iter()
    }
    /// Store the primitive objects of card data. Terminal-sourced tags are ignored: a card
    /// must never be able to overwrite terminal data.
    pub fn store_card_data(&mut self, nodes: &[Tlv<'_>]) -> Result<(), TlvError> {
        let map = &mut self.map;
        for_each_primitive(nodes, &mut |t| {
            if !tags::is_terminal_source(t.tag) {
                map.insert(t.tag, t.value.to_vec());
            }
        })
    }
    /// Store every primitive object (used for terminal-side configuration TLVs).
    pub fn store_all(&mut self, buf: &[u8]) -> Result<(), TlvError> {
        let nodes = parse(buf)?;
        let map = &mut self.map;
        for_each_primitive(&nodes, &mut |t| {
            map.insert(t.tag, t.value.to_vec());
        })
    }
    /// A copy of the selected tags that are present.
    pub fn subset(&self, tags: &[u32]) -> BTreeMap<u32, Vec<u8>> {
        tags.iter().filter_map(|t| self.map.get(t).map(|v| (*t, v.clone()))).collect()
    }
    pub fn to_map(&self) -> BTreeMap<u32, Vec<u8>> {
        self.map.clone()
    }
}
