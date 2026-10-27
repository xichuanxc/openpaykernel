//! Unit tests for the primitives: TLV, DOL, SHA-1, RSA, CAPK, PIN block, Level-1 errors.

use openpaykernel::apdu::{self, TransmissionError};
use openpaykernel::tlv::{self, TlvDb};
use openpaykernel::{
    crypto, dol, AidConfig, AppCandidate, Capk, CapkStore, ContactHost, ContactKernel, EntryPoint, Environment,
    MastercardKernel, OnlineResponse, Status, TerminalConfig, Transaction, VisaKernel,
};
use std::collections::BTreeMap;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn tlv_nested_find_and_roundtrip() {
    let raw = unhex("6F1A840E315041592E5359532E4444463031A5088801025F2D02656E");
    let nodes = tlv::parse(&raw).unwrap();
    assert_eq!(nodes[0].tag, 0x6F);
    assert_eq!(tlv::find(&raw, 0x88).unwrap().value, &[0x02]);
    assert_eq!(tlv::find(&raw, 0x5F2D).unwrap().value, b"en");
    assert_eq!(tlv::encode(nodes[0].tag, nodes[0].value), raw);
}

#[test]
fn tlv_long_lengths_padding_and_errors() {
    let enc = tlv::encode(0x9F46, &[0u8; 200]);
    assert_eq!(&enc[..4], &unhex("9F4681C8")[..]);
    let mut padded = vec![0x00, 0x00];
    padded.extend_from_slice(&enc);
    padded.push(0xFF);
    assert_eq!(tlv::parse(&padded).unwrap()[0].value.len(), 200);
    assert!(tlv::parse(&unhex("9F0205000000")).is_err());
    assert!(tlv::parse(&unhex("9F")).is_err());
}

#[test]
fn card_data_cannot_overwrite_terminal_tags() {
    let mut db = TlvDb::new();
    db.set(0x9F33, &[0xE0, 0xF8, 0xC8]);
    let card = unhex("70099F3303000000500141");
    db.store_card_data(&tlv::parse(&card).unwrap()).unwrap();
    assert_eq!(db.get(0x9F33).unwrap(), &[0xE0, 0xF8, 0xC8]);
    assert_eq!(db.get(0x50).unwrap(), b"A");
}

#[test]
fn dol_padding_rules() {
    let mut db = TlvDb::new();
    db.set(0x9F02, &unhex("000000001000"));
    db.set(0x5A, &unhex("4761739001010010"));
    db.set(0x50, b"VISA");
    db.set(0x9F37, &unhex("11223344"));
    let d = unhex("9F02045A0A50069F37029F4C087004");
    let out = dol::build_dol(&d, &db).unwrap();
    let mut want = unhex("00001000");
    want.extend(unhex("4761739001010010FFFF"));
    want.extend(b"VISA\0\0");
    want.extend(unhex("1122"));
    want.extend([0u8; 12]);
    assert_eq!(out, want);
}

#[test]
fn sha1_known_answers() {
    assert_eq!(crypto::sha1(b"abc").to_vec(), unhex("A9993E364706816ABA3E25717850C26C9CD0D89D"));
    assert_eq!(
        crypto::sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
        unhex("84983E441C3BD26EBAAE4AA1F95129E5E54670F1")
    );
}

#[test]
fn rsa_public_small_values() {
    let n = unhex("D431BD6D3F7B2C0F");
    assert_eq!(crypto::rsa_public(&n, &[3], &unhex("0000000000000123")).unwrap(), unhex("000000000178027B"));
    assert_eq!(crypto::rsa_public(&n, &[1], &unhex("D431BD6D3F7B2C10")).unwrap(), unhex("0000000000000001"));
    assert!(crypto::rsa_public(&unhex("D431BD6D3F7B2C10"), &[3], &[0; 8]).is_none());
    // even modulus
}

#[test]
fn capk_checksum_and_expiry() {
    let mut k = Capk::new([0xA0, 0, 0, 0, 3], 0x92, vec![1; 128], vec![3], "251231");
    k.checksum = Some(k.computed_checksum());
    let mut store = CapkStore::new();
    store.add(k.clone()).unwrap();
    assert!(store.find(&k.rid, 0x92, Some("251231")).is_some());
    assert!(store.find(&k.rid, 0x92, Some("260101")).is_none());
    let mut bad = k;
    bad.checksum = Some([0; 20]);
    assert!(store.add(bad).is_err());
}

#[test]
fn pin_block_format_2() {
    assert_eq!(apdu::plaintext_pin_block("1234").unwrap().to_vec(), unhex("241234FFFFFFFFFF"));
    assert!(apdu::plaintext_pin_block("12a4").is_none());
    assert!(apdu::plaintext_pin_block("123").is_none());
}

struct NoHost;
impl ContactHost for NoHost {
    fn choose_application(&mut self, _: &[AppCandidate]) -> Option<usize> {
        Some(0)
    }
    fn enter_pin(&mut self, _: bool, _: Option<u8>) -> Option<String> {
        None
    }
    fn go_online(&mut self, _: &BTreeMap<u32, Vec<u8>>) -> Option<OnlineResponse> {
        None
    }
}

fn env() -> Environment {
    let mut visa = AidConfig::new(&unhex("A0000000031010"));
    visa.kernel_id = 3;
    Environment::new(TerminalConfig::default(), vec![visa], CapkStore::new(), Box::new(|b: &mut [u8]| b.fill(0)))
}

#[test]
fn level1_error_gives_an_outcome() {
    let mut removed = |_: &[u8]| -> Result<Vec<u8>, TransmissionError> { Err(TransmissionError) };
    let out = EntryPoint::new(env(), vec![Box::new(VisaKernel), Box::new(MastercardKernel)]).process(
        &mut removed,
        &Transaction::new(100),
        None,
    );
    assert_eq!(out.status, Status::TryAgain);
    let res = ContactKernel::new(env(), NoHost).process(&mut removed, &Transaction::new(100), None);
    assert_eq!(res.outcome.status, Status::EndApplication);
    assert_eq!(res.outcome.error.l1, openpaykernel::outcome::L1Error::Transmission);
}
