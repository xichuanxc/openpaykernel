"""A configurable simulated EMV card (contact and contactless).

The card is a test double. Its cryptograms are SHA-1 based stand-ins, not real issuer
3DES/AES MACs. Everything an L2 kernel can check (TLV structure, ODA signatures and
certificates, status words, PIN try counters, CDA transaction hashes) is real.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .. import dol, tlv
from ..capk import CAPK
from . import rsa

enc = tlv.encode

MASTERCARD_AID = bytes.fromhex("A0000000041010")
VISA_AID = bytes.fromhex("A0000000031010")
UNIONPAY_AID = bytes.fromhex("A000000333010102")
DISCOVER_AID = bytes.fromhex("A0000001523010")
AMEX_AID = bytes.fromhex("A00000002501")
TEST_RID_INDEX = 0x92


@dataclass
class Keys:
    ca: rsa.RsaKey
    issuer: rsa.RsaKey
    icc: rsa.RsaKey

    def capk(self, rid: bytes, index: int = TEST_RID_INDEX) -> CAPK:
        k = CAPK(rid, index, self.ca.modulus, self.ca.exponent, "491231")
        return CAPK(rid, index, self.ca.modulus, self.ca.exponent, "491231", checksum=k.computed_checksum())


_KEYS: dict[str, Keys] = {}


def test_keys(seed: str = "openpaykernel") -> Keys:
    if seed not in _KEYS:
        _KEYS[seed] = Keys(rsa.generate(1024, seed + "/ca"), rsa.generate(1024, seed + "/issuer"),
                           rsa.generate(768, seed + "/icc"))
    return _KEYS[seed]


@dataclass
class CardProfile:
    aid: bytes
    label: bytes = b"TEST CARD"
    kind: str = "contact"                 # 'contact', 'visa', 'mastercard'
    pan: bytes = bytes.fromhex("4761739001010010")
    psn: bytes = b"\x01"
    expiry: bytes = bytes.fromhex("301231")   # YYMMDD
    effective: bytes = bytes.fromhex("200101")
    aip: bytes = bytes.fromhex("3C00")       # SDA, DDA, CVM, TRM
    oda: str = "dda"                         # 'sda', 'dda', 'cda', 'none'
    cvm_list: bytes = bytes.fromhex("00000000000000004103420302031E031F00")
    iac_default: bytes = bytes.fromhex("0000000000")
    iac_denial: bytes = bytes.fromhex("0000000000")
    iac_online: bytes = bytes.fromhex("0000000000")
    auc: bytes = bytes.fromhex("FF00")
    issuer_country: bytes = bytes.fromhex("0840")
    app_currency: bytes = bytes.fromhex("0840")
    app_version: bytes = bytes.fromhex("0002")
    pin: str = "1234"
    pin_tries: int = 3
    atc: int = 0x0010
    last_online_atc: int = 0x000C
    lcol: int | None = None
    ucol: int | None = None
    offline_limit: int = 5000               # card decides TC for amounts up to this (minor units)
    decision: str = "auto"                  # 'auto', 'online', 'decline', 'approve'
    online_approve_second_ac: bool = True
    ctq: bytes | None = None                # Visa 9F6C
    pdol: bytes | None = None
    cdol1: bytes = bytes.fromhex("9F02069F03069F1A0295055F2A029A039C019F37049F35019F34039F33039F2103")
    cdol2: bytes = bytes.fromhex("8A029F02069F03069F1A0295055F2A029A039C019F3704")
    ddol: bytes | None = None
    gpo_sw: int = 0x9000
    gac_sw: int = 0x9000
    extra_gpo: bytes = b""                  # additional TLVs in a format-2 GPO response
    in_pse: bool = True
    priority: int = 1
    keys: Keys = field(default_factory=test_keys)
    corrupt_sdad: bool = False
    extra_fci: bytes = b""


class SimCard:
    def __init__(self, *profiles: CardProfile) -> None:
        self.profiles = list(profiles)
        self.current: CardProfile | None = None
        self.records: dict[tuple[int, int], bytes] = {}
        self.afl = b""
        self.pdol_data = b""
        self.cdol1_data = b""
        self.challenge = b""
        self.ac_count = 0
        self.log: list[tuple[bytes, bytes]] = []
        self.icc_dyn_number = bytes.fromhex("0123456789ABCDEF")
        self.script_commands: list[bytes] = []
        self.external_auth: list[bytes] = []
        self._dir_records: dict[int, bytes] = {}

    # ------------------------------------------------------------------ transport
    def transmit(self, c: bytes) -> bytes:
        rsp = self._dispatch(c)
        self.log.append((c, rsp))
        return rsp

    def _dispatch(self, c: bytes) -> bytes:
        cla, ins, p1, p2 = c[0], c[1], c[2], c[3]
        data = c[5:5 + c[4]] if len(c) > 5 else b""
        if ins == 0xA4:
            return self._select(data, p2)
        if ins == 0xB2:
            return self._read_record(p1, p2 >> 3)
        if self.current is None:
            return b"\x69\x85"
        if ins == 0xA8:
            return self._gpo(data)
        if ins == 0xAE:
            return self._generate_ac(p1, data)
        if ins == 0x88:
            return self._internal_auth(data)
        if ins == 0xCA:
            return self._get_data((p1 << 8) | p2)
        if ins == 0x84:
            self.challenge = hashlib.sha1(b"chal" + bytes([self.ac_count])).digest()[:8]
            return self.challenge + b"\x90\x00"
        if ins == 0x20:
            return self._verify(p2, data)
        if ins == 0x82:
            self.external_auth.append(data)
            return b"\x90\x00"
        if cla & 0xF0 == 0x80 or cla == 0x84:
            self.script_commands.append(c)
            return b"\x90\x00"
        return b"\x6D\x00"

    # ------------------------------------------------------------------ selection
    def _select(self, name: bytes, p2: int) -> bytes:
        if name in (b"2PAY.SYS.DDF01", b"1PAY.SYS.DDF01"):
            return self._directory(name)
        matches = [p for p in self.profiles if p.aid.startswith(name)]
        idx = 0 if p2 & 0x02 == 0 else (self._last_sel_idx + 1)
        self._last_sel_idx = idx
        if idx >= len(matches):
            return b"\x6A\x82"
        p = matches[idx]
        self._activate(p)
        a5 = enc(0x50, p.label) + enc(0x87, bytes([p.priority]))
        if p.pdol:
            a5 += enc(0x9F38, p.pdol)
        a5 += p.extra_fci
        return enc(0x6F, enc(0x84, p.aid) + enc(0xA5, a5)) + b"\x90\x00"

    _last_sel_idx = 0

    def _directory(self, name: bytes) -> bytes:
        contactless = name.startswith(b"2")
        entries = b""
        for p in self.profiles:
            if not contactless and not p.in_pse:
                continue
            e = enc(0x4F, p.aid) + enc(0x50, p.label) + enc(0x87, bytes([p.priority]))
            entries += enc(0x61, e)
        if contactless:
            return enc(0x6F, enc(0x84, name) + enc(0xA5, enc(0xBF0C, entries))) + b"\x90\x00"
        self._dir_records = {1: enc(0x70, entries)} if entries else {}
        return enc(0x6F, enc(0x84, name) + enc(0xA5, enc(0x88, b"\x01"))) + b"\x90\x00"

    def _read_record(self, rec: int, sfi: int) -> bytes:
        if self.current is None and sfi == 1 and self._dir_records:
            r = self._dir_records.get(rec)
            return r + b"\x90\x00" if r else b"\x6A\x83"
        r = self.records.get((sfi, rec))
        return r + b"\x90\x00" if r else b"\x6A\x83"

    # ------------------------------------------------------------------ personalisation
    def _activate(self, p: CardProfile) -> None:
        self.current = p
        k = p.keys
        exp_mmyy = bytes([p.expiry[1], p.expiry[0]])
        pan_cn = p.pan
        # SFI 1: data covered by ODA
        r1 = enc(0x5A, pan_cn) + enc(0x5F24, p.expiry) + enc(0x5F25, p.effective) + enc(0x5F34, p.psn) \
            + enc(0x9F07, p.auc) + enc(0x5F28, p.issuer_country) + enc(0x9F42, p.app_currency) \
            + enc(0x9F08, p.app_version) + enc(0x8E, p.cvm_list) + enc(0x9F0D, p.iac_default) \
            + enc(0x9F0E, p.iac_denial) + enc(0x9F0F, p.iac_online)
        t2 = p.pan.hex().upper().rstrip("F") + "D" + p.expiry.hex()[:4] + "2010000000000"
        track2 = bytes.fromhex(t2 + ("F" if len(t2) % 2 else ""))
        r2 = enc(0x57, track2) + enc(0x8C, p.cdol1) + enc(0x8D, p.cdol2) + enc(0x9F4A, b"\x82")
        if p.lcol is not None:
            r2 += enc(0x9F14, bytes([p.lcol])) + enc(0x9F23, bytes([p.ucol or 0]))
        if p.ddol:
            r2 += enc(0x9F49, p.ddol)
        rec1, rec2 = enc(0x70, r1), enc(0x70, r2)
        static = r1 + r2 + p.aip
        issuer_cert, issuer_rem = rsa.issuer_certificate(k.ca, k.issuer, pan_cn[:3], exp_mmyy)
        icc_cert, icc_rem = rsa.icc_certificate(k.issuer, k.icc, pan_cn, exp_mmyy, static)
        r3 = enc(0x8F, bytes([TEST_RID_INDEX])) + enc(0x90, issuer_cert) + enc(0x92, issuer_rem) \
            + enc(0x9F32, k.issuer.exponent)
        r4 = enc(0x9F46, icc_cert) + enc(0x9F48, icc_rem) + enc(0x9F47, k.icc.exponent)
        # Records are kept under the 256-byte short-APDU response limit, as on a real card.
        sfi2 = [enc(0x70, r3)]
        if p.oda in ("dda", "cda") or p.kind in ("visa", "unionpay"):
            sfi2.append(enc(0x70, r4))
        if p.oda == "sda":
            sfi2.append(enc(0x70, enc(0x93, rsa.signed_static_data(k.issuer, static))))
        self.records = {(1, 1): rec1, (1, 2): rec2}
        for i, rec in enumerate(sfi2, 1):
            assert len(rec) <= 256, "simulated record exceeds short APDU response size"
            self.records[(2, i)] = rec
        afl = bytes([1 << 3, 1, 2, 2, 2 << 3, 1, len(sfi2), 0])
        self.afl = afl

    # ------------------------------------------------------------------ transaction
    def _gpo(self, data: bytes) -> bytes:
        p = self.current
        if p.gpo_sw != 0x9000:
            return p.gpo_sw.to_bytes(2, "big")
        n = tlv.parse(data)
        if not n or n[0].tag != 0x83:
            return b"\x67\x00"
        self.pdol_data = n[0].value
        self.atc_value = p.atc + 1
        if p.kind in ("visa", "unionpay"):
            return self._visa_gpo()
        if p.kind == "discover":  # AIP, AFL and Card Processing Requirements (9F71)
            body = enc(0x82, p.aip) + enc(0x94, self.afl) + (enc(0x9F71, p.ctq) if p.ctq else b"")
            return enc(0x77, body) + b"\x90\x00"
        return enc(0x77, enc(0x82, p.aip) + enc(0x94, self.afl) + p.extra_gpo) + b"\x90\x00"

    def _pdol_values(self) -> dict[int, bytes]:
        out, pos = {}, 0
        for tag, length in dol.parse_dol(self.current.pdol or b""):
            out[tag] = self.pdol_data[pos:pos + length]
            pos += length
        return out

    def _visa_gpo(self) -> bytes:
        p = self.current
        v = self._pdol_values()
        ttq = v.get(0x9F66, bytes(4))
        a = v.get(0x9F02, b"\x00").hex()
        amount = int(a) if a.isdigit() else 0
        if p.decision == "decline":
            ctype = 0x00
        elif p.decision == "online" or ttq[1] & 0x80 or amount > p.offline_limit:
            ctype = 0x80
        else:
            ctype = 0x40
        iad = bytes([0x06, 0x01, 0x0A, 0x03, (ctype >> 6) << 4, 0x00, 0x00])
        atc = self.atc_value.to_bytes(2, "big")
        ac = self._mac(self.pdol_data + atc)
        body = enc(0x82, p.aip) + enc(0x94, self.afl) + enc(0x9F36, atc) + enc(0x9F26, ac) \
            + enc(0x9F10, iad) + enc(0x9F27, bytes([ctype]))
        if p.ctq:
            body += enc(0x9F6C, p.ctq)
        body += enc(0x9F6E, bytes.fromhex("20700000"))
        if p.kind == "unionpay":
            body += enc(0x9F5D, bytes.fromhex("000000050000"))  # available offline spending amount
        if ctype == 0x40 and p.aip[0] & 0x20:
            card_auth = b"\x01" + hashlib.sha1(b"cardun").digest()[:4] + (p.ctq or b"\x00\x00")
            body += enc(0x9F69, card_auth)
            un = v.get(0x9F37, bytes(4))
            tdd = un + v.get(0x9F02, bytes(6)) + v.get(0x5F2A, bytes(2)) + card_auth
            icc_dd = bytes([len(self.icc_dyn_number)]) + self.icc_dyn_number
            sdad = rsa.signed_dynamic_data(p.keys.icc, icc_dd, tdd)
            if p.corrupt_sdad:
                sdad = sdad[:-1] + bytes([sdad[-1] ^ 1])
            body += enc(0x9F4B, sdad)
        return enc(0x77, body) + b"\x90\x00"

    def _mac(self, data: bytes) -> bytes:
        return hashlib.sha1(b"issuer-key" + self.current.pan + data).digest()[:8]

    def _generate_ac(self, p1: int, data: bytes) -> bytes:
        p = self.current
        if p.gac_sw != 0x9000:
            return p.gac_sw.to_bytes(2, "big")
        req = p1 & 0xC0
        cda = bool(p1 & 0x10)
        first = self.ac_count == 0
        self.ac_count += 1
        if first:
            self.cdol1_data = data
        if first:
            if p.decision == "decline" or req == 0x00:
                ctype = 0x00
            elif p.decision == "online" or req == 0x80:
                ctype = 0x80
            else:
                ctype = 0x40
        else:
            ctype = 0x40 if (req == 0x40 and p.online_approve_second_ac) else 0x00
        atc = self.atc_value.to_bytes(2, "big")
        ac = self._mac(data + atc)
        iad = bytes([0x06, 0x01, 0x0A, 0x03, 0xA0, 0x00, 0x00])
        cid = bytes([ctype])
        supports_cda = p.oda == "cda" and p.aip[0] & 0x01
        if cda and supports_cda and ctype != 0x00:
            tlvs = enc(0x9F27, cid) + enc(0x9F36, atc) + enc(0x9F10, iad)
            hash_input = self.pdol_data + self.cdol1_data + (data if not first else b"") + tlvs
            dyn = bytes([len(self.icc_dyn_number)]) + self.icc_dyn_number + cid + ac \
                + hashlib.sha1(hash_input).digest()
            un = self._cdol_value(p.cdol1 if first else p.cdol2, data, 0x9F37)
            sdad = rsa.signed_dynamic_data(p.keys.icc, dyn, un)
            if p.corrupt_sdad:
                sdad = sdad[:-1] + bytes([sdad[-1] ^ 1])
            return enc(0x77, tlvs + enc(0x9F4B, sdad)) + b"\x90\x00"
        if p.kind == "contact" and not cda:
            return enc(0x80, cid + atc + ac + iad) + b"\x90\x00"
        return enc(0x77, enc(0x9F27, cid) + enc(0x9F36, atc) + enc(0x9F26, ac) + enc(0x9F10, iad)) + b"\x90\x00"

    @staticmethod
    def _cdol_value(cdol: bytes, data: bytes, want: int) -> bytes:
        pos = 0
        for tag, length in dol.parse_dol(cdol):
            if tag == want:
                return data[pos:pos + length]
            pos += length
        return b""

    def _internal_auth(self, data: bytes) -> bytes:
        p = self.current
        icc_dd = bytes([len(self.icc_dyn_number)]) + self.icc_dyn_number
        sdad = rsa.signed_dynamic_data(p.keys.icc, icc_dd, data)
        if p.corrupt_sdad:
            sdad = sdad[:-1] + bytes([sdad[-1] ^ 1])
        return enc(0x80, sdad) + b"\x90\x00"

    def _get_data(self, tag: int) -> bytes:
        p = self.current
        if tag == 0x9F17:
            return enc(0x9F17, bytes([p.pin_tries])) + b"\x90\x00"
        if tag == 0x9F36:
            return enc(0x9F36, (p.atc + 1).to_bytes(2, "big")) + b"\x90\x00"
        if tag == 0x9F13:
            return enc(0x9F13, p.last_online_atc.to_bytes(2, "big")) + b"\x90\x00"
        return b"\x6A\x88"

    def _verify(self, p2: int, data: bytes) -> bytes:
        p = self.current
        if p.pin_tries == 0:
            return b"\x69\x83"
        if p2 == 0x88:
            block = p.keys.icc.private(data)
            if block[0] != 0x7F or block[9:17] != self.challenge:
                return b"\x69\x85"
            data = block[1:9]
        expected = bytes.fromhex(f"2{len(p.pin):X}{p.pin}".ljust(16, "F"))
        if data == expected:
            p.pin_tries = 3
            return b"\x90\x00"
        p.pin_tries -= 1
        return bytes([0x63, 0xC0 | p.pin_tries])
