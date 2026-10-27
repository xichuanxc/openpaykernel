//! ISO 7816-4 / EMV command APDUs and the reader abstraction.

use alloc::vec::Vec;

use crate::tlv;

/// A Level-1 error reported by the reader: no card, card removed, timeout, communication error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmissionError;

/// The only hardware interface the kernel needs.
///
/// `transmit` receives a complete command APDU (`CLA INS P1 P2 [Lc data] [Le]`) and must
/// return the response data followed by `SW1 SW2`. `61xx`/`6Cxx` handling is done by the kernel.
pub trait Reader {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8>, TransmissionError>;
}

impl<F: FnMut(&[u8]) -> Result<Vec<u8>, TransmissionError>> Reader for F {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8>, TransmissionError> {
        self(capdu)
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl Response {
    pub fn ok(&self) -> bool {
        self.sw == 0x9000
    }
    fn from_raw(raw: Vec<u8>) -> Result<Self, TransmissionError> {
        if raw.len() < 2 {
            return Err(TransmissionError);
        }
        let n = raw.len();
        let sw = u16::from_be_bytes([raw[n - 2], raw[n - 1]]);
        let mut data = raw;
        data.truncate(n - 2);
        Ok(Response { data, sw })
    }
}

/// Wraps a [`Reader`]: handles GET RESPONSE / wrong Le and keeps an APDU log.
pub struct Channel<'r> {
    reader: &'r mut dyn Reader,
    /// Every (command, response) pair exchanged.
    pub log: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<'r> Channel<'r> {
    pub fn new(reader: &'r mut dyn Reader) -> Self {
        Channel { reader, log: Vec::new() }
    }

    pub fn exchange(&mut self, capdu: &[u8]) -> Result<Response, TransmissionError> {
        let raw = self.reader.transmit(capdu)?;
        if raw.len() > 258 {
            return Err(TransmissionError); // short APDU: at most 256 data bytes + SW1 SW2
        }
        self.log.push((capdu.to_vec(), raw.clone()));
        let rsp = Response::from_raw(raw)?;
        if rsp.sw >> 8 == 0x61 {
            let gr = [0x00, 0xC0, 0x00, 0x00, rsp.sw as u8];
            let raw = self.reader.transmit(&gr)?;
            self.log.push((b"GETRSP".to_vec(), raw.clone()));
            return Response::from_raw(raw);
        }
        if rsp.sw >> 8 == 0x6C && !capdu.is_empty() {
            let mut again = capdu.to_vec();
            let last = again.len() - 1;
            again[last] = rsp.sw as u8;
            let raw = self.reader.transmit(&again)?;
            self.log.push((again, raw.clone()));
            return Response::from_raw(raw);
        }
        Ok(rsp)
    }
}

fn cmd(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + data.len());
    out.extend_from_slice(&[cla, ins, p1, p2]);
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if let Some(le) = le {
        out.push(le);
    }
    out
}

pub const AAC: u8 = 0x00;
pub const TC: u8 = 0x40;
pub const ARQC: u8 = 0x80;
pub const CDA_REQUESTED: u8 = 0x10;

pub fn select(name: &[u8], first: bool) -> Vec<u8> {
    cmd(0x00, 0xA4, 0x04, if first { 0x00 } else { 0x02 }, name, Some(0))
}
pub fn read_record(sfi: u8, record: u8) -> Vec<u8> {
    cmd(0x00, 0xB2, record, (sfi << 3) | 0x04, &[], Some(0))
}
pub fn get_processing_options(pdol_data: &[u8]) -> Vec<u8> {
    cmd(0x80, 0xA8, 0x00, 0x00, &tlv::encode(0x83, pdol_data), Some(0))
}
pub fn generate_ac(ref_control: u8, cdol_data: &[u8]) -> Vec<u8> {
    cmd(0x80, 0xAE, ref_control, 0x00, cdol_data, Some(0))
}
pub fn internal_authenticate(ddol_data: &[u8]) -> Vec<u8> {
    cmd(0x00, 0x88, 0x00, 0x00, ddol_data, Some(0))
}
pub fn get_data(tag: u16) -> Vec<u8> {
    cmd(0x80, 0xCA, (tag >> 8) as u8, tag as u8, &[], Some(0))
}
pub fn get_challenge() -> Vec<u8> {
    cmd(0x00, 0x84, 0x00, 0x00, &[], Some(0))
}
/// qualifier 0x80 = plaintext PIN, 0x88 = enciphered PIN.
pub fn verify(pin_block: &[u8], qualifier: u8) -> Vec<u8> {
    cmd(0x00, 0x20, 0x00, qualifier, pin_block, None)
}
pub fn external_authenticate(data: &[u8]) -> Vec<u8> {
    cmd(0x00, 0x82, 0x00, 0x00, data, None)
}

/// ISO 9564 format 2 PIN block used by VERIFY. Returns None if the PIN is not 4..12 digits.
pub fn plaintext_pin_block(pin: &str) -> Option<[u8; 8]> {
    let d = pin.as_bytes();
    if !(4..=12).contains(&d.len()) || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut nib = [0xFu8; 16];
    nib[0] = 2;
    nib[1] = d.len() as u8;
    for (i, c) in d.iter().enumerate() {
        nib[2 + i] = c - b'0';
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = (nib[2 * i] << 4) | nib[2 * i + 1];
    }
    Some(out)
}
