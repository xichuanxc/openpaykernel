//! Data Object Lists (EMV Book 3, section 5.4).

use alloc::vec::Vec;

use crate::tags::{self, Format};
use crate::tlv::{self, TlvDb, TlvError};

/// Most data a DOL may produce, so the command still fits a short APDU (e.g. `83 81 FC <data>`).
pub const MAX_COMMAND_DATA: usize = 252;

pub fn parse_dol(dol: &[u8]) -> Result<Vec<(u32, usize)>, TlvError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < dol.len() {
        let tag = tlv::parse_tag(dol, &mut pos)?;
        let len = tlv::parse_length(dol, &mut pos)?;
        out.push((tag, len));
    }
    Ok(out)
}

pub fn dol_tags(dol: &[u8]) -> Vec<u32> {
    parse_dol(dol).map(|v| v.into_iter().map(|(t, _)| t).collect()).unwrap_or_default()
}

pub fn contains(dol: &[u8], tag: u32) -> bool {
    dol_tags(dol).contains(&tag)
}

/// Pad or truncate a value to a DOL entry length (Book 3 5.4 rules).
pub fn fit(value: &[u8], length: usize, fmt: Format, out: &mut Vec<u8>) {
    let n = value.len();
    if n == length {
        out.extend_from_slice(value);
    } else if fmt == Format::N {
        if n > length {
            out.extend_from_slice(&value[n - length..]);
        } else {
            out.resize(out.len() + (length - n), 0);
            out.extend_from_slice(value);
        }
    } else {
        let take = n.min(length);
        out.extend_from_slice(&value[..take]);
        let pad = if fmt == Format::Cn { 0xFF } else { 0x00 };
        out.resize(out.len() + (length - take), pad);
    }
}

/// Concatenate the values requested by a DOL. Missing data and constructed tags are zero-filled.
pub fn build_dol(dol: &[u8], db: &TlvDb) -> Result<Vec<u8>, TlvError> {
    let mut out = Vec::new();
    for (tag, len) in parse_dol(dol)? {
        if len > MAX_COMMAND_DATA {
            return Err(TlvError);
        }
        match db.get(tag) {
            Some(v) if !tlv::is_constructed(tag) => fit(v, len, tags::format(tag), &mut out),
            _ => out.resize(out.len() + len, 0),
        }
        if out.len() > MAX_COMMAND_DATA * 4 {
            return Err(TlvError);
        }
    }
    Ok(out)
}
