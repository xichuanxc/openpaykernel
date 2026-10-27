//! The parts of the EMV data dictionary a kernel needs at run time: format and source.
//! Mirrors `python/openpaykernel/tags.py`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Numeric BCD, right-justified with leading zeros.
    N,
    /// Compressed numeric, left-justified, padded with 'F'.
    Cn,
    /// an / ans text.
    A,
    /// Binary.
    B,
}

const NUMERIC: &[u32] = &[
    0x42, 0x9A, 0x9C, 0x5F24, 0x5F25, 0x5F28, 0x5F2A, 0x5F30, 0x5F34, 0x5F36, 0x9F01, 0x9F02, 0x9F03, 0x9F11, 0x9F15,
    0x9F1A, 0x9F21, 0x9F35, 0x9F39, 0x9F41, 0x9F42, 0x9F44, 0xDF8123, 0xDF8124, 0xDF8125, 0xDF8126,
];
const COMPRESSED: &[u32] = &[0x5A, 0x9F20];
const TEXT: &[u32] =
    &[0x50, 0x56, 0x89, 0x8A, 0x5F20, 0x5F2D, 0x5F50, 0x9F12, 0x9F16, 0x9F1C, 0x9F1E, 0x9F1F, 0x9F4E, 0x9F53];
const TERMINAL: &[u32] = &[
    0x95, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x5F2A, 0x5F36, 0x9F01, 0x9F02, 0x9F03, 0x9F06, 0x9F09, 0x9F15, 0x9F16, 0x9F1A,
    0x9F1B, 0x9F1C, 0x9F1D, 0x9F1E, 0x9F21, 0x9F33, 0x9F34, 0x9F35, 0x9F37, 0x9F39, 0x9F40, 0x9F41, 0x9F4E, 0x9F53,
    0x9F66, 0x9F6D, 0x9F7E,
];

pub fn format(tag: u32) -> Format {
    if NUMERIC.contains(&tag) {
        Format::N
    } else if COMPRESSED.contains(&tag) {
        Format::Cn
    } else if TEXT.contains(&tag) {
        Format::A
    } else {
        Format::B
    }
}

/// True for data elements whose source is the terminal (including all DF81xx kernel data).
pub fn is_terminal_source(tag: u32) -> bool {
    (0xDF8100..=0xDF81FF).contains(&tag) || TERMINAL.contains(&tag)
}
