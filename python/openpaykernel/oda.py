"""Offline Data Authentication: SDA, DDA, fDDA and CDA (EMV Book 2, sections 5 and 6).

Only RSA with SHA-1 is implemented. These are the algorithms EMVCo currently mandates for
deployed cards. ECC (Book E) is not covered yet.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .capk import CAPK, CAPKStore
from .tlv import TLVError, parse, parse_tag_list


class OdaError(Exception):
    pass


@dataclass
class PublicKey:
    modulus: bytes
    exponent: bytes

    @property
    def size(self) -> int:
        return len(self.modulus)

    def recover(self, data: bytes) -> bytes:
        """Apply the public key (RSA "recovery")."""
        if len(data) != self.size:
            raise OdaError("certificate length differs from key modulus length")
        n = int.from_bytes(self.modulus, "big")
        e = int.from_bytes(self.exponent, "big")
        return pow(int.from_bytes(data, "big"), e, n).to_bytes(self.size, "big")


def _check_frame(rec: bytes, fmt: int) -> None:
    if rec[0] != 0x6A or rec[-1] != 0xBC:
        raise OdaError("recovered data header/trailer invalid")
    if rec[1] != fmt:
        raise OdaError(f"certificate format {rec[1]:02X} != {fmt:02X}")


def _check_hash(rec: bytes, extra: bytes) -> None:
    if hashlib.sha1(rec[1:-21] + extra).digest() != rec[-21:-1]:
        raise OdaError("hash result mismatch")


def _expired(mmyy: bytes, today_yymmdd: str) -> bool:
    mm, yy = mmyy.hex()[:2], mmyy.hex()[2:]
    cert = (2000 + int(yy) if int(yy) < 50 else 1900 + int(yy)) * 100 + int(mm)
    t = (2000 + int(today_yymmdd[:2]) if int(today_yymmdd[:2]) < 50 else 1900 + int(today_yymmdd[:2])) * 100 \
        + int(today_yymmdd[2:4])
    return cert < t


def _pan_matches(prefix_cn: bytes, pan: bytes) -> bool:
    """Leftmost PAN digits embedded in a certificate, padded with 'F'."""
    p = prefix_cn.hex().upper().rstrip("F")
    return pan.hex().upper().rstrip("F").startswith(p) and len(p) >= 3


def recover_issuer_pk(capk: CAPK, cert: bytes, remainder: bytes | None, exponent: bytes,
                      pan: bytes, today: str, store: CAPKStore | None = None) -> PublicKey:
    ca = PublicKey(capk.modulus, capk.exponent)
    rec = ca.recover(cert)
    _check_frame(rec, 0x02)
    _check_hash(rec, (remainder or b"") + exponent)
    issuer_id, expiry, serial = rec[2:6], rec[6:8], rec[8:11]
    if not _pan_matches(issuer_id, pan):
        raise OdaError("issuer identifier does not match PAN")
    if _expired(expiry, today):
        raise OdaError("issuer certificate expired")
    if store and store.is_revoked(capk.rid, capk.index, serial):
        raise OdaError("issuer certificate revoked")
    if rec[11] != 0x01 or rec[12] != 0x01:
        raise OdaError("unsupported hash or PK algorithm")
    ni = rec[13]
    in_cert = len(rec) - 36
    modulus = rec[15:15 + min(ni, in_cert)]
    if ni > in_cert:
        if not remainder or len(remainder) != ni - in_cert:
            raise OdaError("issuer PK remainder missing or wrong length")
        modulus += remainder
    return PublicKey(modulus, exponent)


def recover_icc_pk(issuer: PublicKey, cert: bytes, remainder: bytes | None, exponent: bytes,
                   static_data: bytes, pan: bytes, today: str) -> PublicKey:
    rec = issuer.recover(cert)
    _check_frame(rec, 0x04)
    _check_hash(rec, (remainder or b"") + exponent + static_data)
    cert_pan = rec[2:12]
    if cert_pan.hex().upper().rstrip("F") != pan.hex().upper().rstrip("F"):
        raise OdaError("ICC certificate PAN mismatch")
    if _expired(rec[12:14], today):
        raise OdaError("ICC certificate expired")
    if rec[17] != 0x01 or rec[18] != 0x01:
        raise OdaError("unsupported hash or PK algorithm")
    nic = rec[19]
    in_cert = len(rec) - 42
    modulus = rec[21:21 + min(nic, in_cert)]
    if nic > in_cert:
        if not remainder or len(remainder) != nic - in_cert:
            raise OdaError("ICC PK remainder missing or wrong length")
        modulus += remainder
    return PublicKey(modulus, exponent)


def verify_sda(issuer: PublicKey, ssad: bytes, static_data: bytes) -> bytes:
    """Return the Data Authentication Code (9F45)."""
    rec = issuer.recover(ssad)
    _check_frame(rec, 0x03)
    _check_hash(rec, static_data)
    return rec[3:5]


@dataclass
class DynamicSignature:
    icc_dynamic_data: bytes

    @property
    def icc_dynamic_number(self) -> bytes:
        n = self.icc_dynamic_data[0]
        return self.icc_dynamic_data[1:1 + n]


def verify_dynamic_signature(icc: PublicKey, sdad: bytes, terminal_dynamic_data: bytes) -> DynamicSignature:
    """DDA / fDDA / CDA common signature check (format 05)."""
    rec = icc.recover(sdad)
    _check_frame(rec, 0x05)
    if rec[2] != 0x01:
        raise OdaError("unsupported hash algorithm")
    ldd = rec[3]
    if 4 + ldd > len(rec) - 21:
        raise OdaError("ICC dynamic data length invalid")
    _check_hash(rec, terminal_dynamic_data)
    return DynamicSignature(rec[4:4 + ldd])


def verify_cda(icc: PublicKey, sdad: bytes, unpredictable_number: bytes, cid: bytes,
               tc_hash_input: bytes) -> tuple[bytes, DynamicSignature]:
    """Verify a CDA signature. tc_hash_input = PDOL data || CDOL data || GENERATE AC TLVs minus 9F4B.

    Returns (application cryptogram, signature).
    """
    sig = verify_dynamic_signature(icc, sdad, unpredictable_number)
    dd = sig.icc_dynamic_data
    n = dd[0]
    if len(dd) < 1 + n + 1 + 8 + 20:
        raise OdaError("CDA ICC dynamic data too short")
    cid_s, ac, tc_hash = dd[1 + n:2 + n], dd[2 + n:10 + n], dd[10 + n:30 + n]
    if cid_s != cid:
        raise OdaError("CID in signature differs from CID in response")
    if hashlib.sha1(tc_hash_input).digest() != tc_hash:
        raise OdaError("transaction data hash mismatch")
    return ac, sig


def static_data_for_record(sfi: int, record: bytes) -> bytes:
    """Contribution of one AFL record to the static data to be authenticated."""
    if sfi <= 10:
        try:
            nodes = parse(record)
        except TLVError as e:
            raise OdaError(str(e))
        if len(nodes) != 1 or nodes[0].tag != 0x70:
            raise OdaError("ODA record not tag 70")
        return nodes[0].value
    return record


def sda_tag_list_data(tag_list: bytes | None, db) -> bytes:
    if not tag_list:
        return b""
    tags = parse_tag_list(tag_list)
    if tags != [0x82]:
        raise OdaError("SDA Tag List must contain only tag 82")
    return db.get(0x82, b"")
