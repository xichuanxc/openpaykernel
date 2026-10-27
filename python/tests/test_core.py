import hashlib

import pytest

from openpaykernel import dol, oda, tlv
from openpaykernel.capk import CAPK, CAPKStore
from openpaykernel.sim import rsa


def test_tlv_roundtrip_and_nested():
    raw = bytes.fromhex("6F1A840E315041592E5359532E4444463031A5088801025F2D02656E")
    nodes = tlv.parse(raw)
    assert nodes[0].tag == 0x6F
    assert tlv.find(nodes, 0x88).value == b"\x02"
    assert tlv.find(nodes, 0x5F2D).value == b"en"
    assert nodes[0].encode() == raw


def test_tlv_long_lengths_and_padding():
    v = bytes(200)
    enc = tlv.encode(0x9F46, v)
    assert enc[:4] == bytes.fromhex("9F4681C8")
    assert tlv.parse(b"\x00\x00" + enc + b"\xFF")[0].value == v
    assert tlv.encode_length(0x1234) == b"\x82\x12\x34"


def test_tlv_errors():
    with pytest.raises(tlv.TLVError):
        tlv.parse(bytes.fromhex("9F0205000000"))
    with pytest.raises(tlv.TLVError):
        tlv.parse(bytes.fromhex("9F"))


def test_dol_padding_rules():
    db = {0x9F02: bytes.fromhex("000000001000"), 0x5A: bytes.fromhex("4761739001010010"),
          0x50: b"VISA", 0x9F37: bytes.fromhex("11223344")}
    d = bytes.fromhex("9F0204" "5A0A" "5006" "9F3702" "9F4C08" "7004")
    out = dol.build_dol(d, db)
    assert out == (bytes.fromhex("00001000")            # n: keep rightmost
                   + bytes.fromhex("4761739001010010FFFF")  # cn: pad F
                   + b"VISA\x00\x00"                  # an: pad 00
                   + bytes.fromhex("1122")            # b: truncate right
                   + bytes(8)                         # missing
                   + bytes(4))                        # constructed → zeros


def test_capk_checksum_and_expiry():
    k = CAPK(b"\xA0\x00\x00\x00\x03", 0x92, b"\x01" * 128, b"\x03", "251231")
    k2 = CAPK(k.rid, k.index, k.modulus, k.exponent, k.expiry, checksum=k.computed_checksum())
    store = CAPKStore()
    store.add(k2)
    assert store.find(k.rid, 0x92, "251231") is not None
    assert store.find(k.rid, 0x92, "260101") is None
    with pytest.raises(ValueError):
        store.add(CAPK(k.rid, 1, k.modulus, k.exponent, checksum=b"\x00" * 20))


def test_certificate_chain_with_remainders():
    ca, iss, icc = rsa.generate(1024, "t/ca"), rsa.generate(1024, "t/iss"), rsa.generate(768, "t/icc")
    capk = CAPK(b"\xA0\x00\x00\x00\x03", 1, ca.modulus, ca.exponent)
    pan = bytes.fromhex("4761739001010010")
    cert, rem = rsa.issuer_certificate(ca, iss, pan[:3], b"\x12\x30")
    assert rem  # 1024-bit issuer under 1024-bit CA needs a remainder
    ipk = oda.recover_issuer_pk(capk, cert, rem, iss.exponent, pan, "261027")
    assert ipk.modulus == iss.modulus
    static = b"static-data"
    c2, r2 = rsa.icc_certificate(iss, icc, pan, b"\x12\x30", static)
    icpk = oda.recover_icc_pk(ipk, c2, r2, icc.exponent, static, pan, "261027")
    assert icpk.modulus == icc.modulus
    with pytest.raises(oda.OdaError):
        oda.recover_icc_pk(ipk, c2, r2, icc.exponent, static + b"x", pan, "261027")
    with pytest.raises(oda.OdaError, match="expired"):
        oda.recover_icc_pk(ipk, c2, r2, icc.exponent, static, pan, "310101")
    # SDA and DDA
    ssad = rsa.signed_static_data(iss, static)
    assert oda.verify_sda(ipk, ssad, static) == b"\xDA\xC1"
    sdad = rsa.signed_dynamic_data(icc, b"\x02\xAB\xCD", b"UN!!")
    assert oda.DynamicSignature(b"\x02\xAB\xCD").icc_dynamic_number == b"\xAB\xCD"
    assert oda.verify_dynamic_signature(icpk, sdad, b"UN!!").icc_dynamic_number == b"\xAB\xCD"
    with pytest.raises(oda.OdaError):
        oda.verify_dynamic_signature(icpk, sdad, b"UN!?")


def test_cda_hash_binding():
    icc = rsa.generate(768, "t/icc")
    pk = oda.PublicKey(icc.modulus, icc.exponent)
    ac = bytes(range(8))
    txdata = b"pdol" + b"cdol" + b"tlvs"
    dyn = b"\x02\x01\x02" + b"\x80" + ac + hashlib.sha1(txdata).digest()
    sdad = rsa.signed_dynamic_data(icc, dyn, b"\x11\x22\x33\x44")
    got, _ = oda.verify_cda(pk, sdad, b"\x11\x22\x33\x44", b"\x80", txdata)
    assert got == ac
    with pytest.raises(oda.OdaError, match="CID"):
        oda.verify_cda(pk, sdad, b"\x11\x22\x33\x44", b"\x40", txdata)
    with pytest.raises(oda.OdaError, match="hash"):
        oda.verify_cda(pk, sdad, b"\x11\x22\x33\x44", b"\x80", txdata + b"!")
