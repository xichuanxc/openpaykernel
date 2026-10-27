"""Small deterministic RSA toolkit for building test cards. Not for production keys."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def _is_probable_prime(n: int, rnd: random.Random, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rnd.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, e: int, rnd: random.Random) -> int:
    while True:
        c = rnd.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if (c - 1) % e and _is_probable_prime(c, rnd):
            return c


@dataclass(frozen=True)
class RsaKey:
    n: int
    e: int
    d: int

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def modulus(self) -> bytes:
        return self.n.to_bytes(self.size, "big")

    @property
    def exponent(self) -> bytes:
        return self.e.to_bytes((self.e.bit_length() + 7) // 8, "big")

    def private(self, block: bytes) -> bytes:
        assert len(block) == self.size
        return pow(int.from_bytes(block, "big"), self.d, self.n).to_bytes(self.size, "big")

    def public(self, block: bytes) -> bytes:
        return pow(int.from_bytes(block, "big"), self.e, self.n).to_bytes(self.size, "big")


def generate(bits: int, seed: str, e: int = 3) -> RsaKey:
    rnd = random.Random(hashlib.sha256(seed.encode()).digest())
    while True:
        p = _prime(bits // 2, e, rnd)
        q = _prime(bits - bits // 2, e, rnd)
        n = p * q
        if p != q and n.bit_length() == bits:
            d = pow(e, -1, (p - 1) * (q - 1))
            return RsaKey(n, e, d)


# --- EMV certificate builders (Book 2 tables 6, 14, 7, 17) --------------------------------

def _sha1(b: bytes) -> bytes:
    return hashlib.sha1(b).digest()


def issuer_certificate(ca: RsaKey, issuer: RsaKey, issuer_id: bytes, expiry_mmyy: bytes,
                       serial: bytes = b"\x00\x00\x01") -> tuple[bytes, bytes]:
    """Return (certificate 90, remainder 92)."""
    nca = ca.size
    room = nca - 36
    mod = issuer.modulus
    body = (b"\x02" + issuer_id.ljust(4, b"\xFF") + expiry_mmyy + serial + b"\x01\x01"
            + bytes([len(mod), len(issuer.exponent)]))
    in_cert = mod[:room].ljust(room, b"\xBB")
    remainder = mod[room:]
    h = _sha1(body + in_cert + remainder + issuer.exponent)
    return ca.private(b"\x6A" + body + in_cert + h + b"\xBC"), remainder


def icc_certificate(issuer: RsaKey, icc: RsaKey, pan: bytes, expiry_mmyy: bytes, static_data: bytes,
                    serial: bytes = b"\x00\x00\x01", fmt: int = 0x04) -> tuple[bytes, bytes]:
    """Return (certificate 9F46, remainder 9F48)."""
    room = issuer.size - 42
    mod = icc.modulus
    body = (bytes([fmt]) + pan.ljust(10, b"\xFF") + expiry_mmyy + serial + b"\x01\x01"
            + bytes([len(mod), len(icc.exponent)]))
    in_cert = mod[:room].ljust(room, b"\xBB")
    remainder = mod[room:]
    h = _sha1(body + in_cert + remainder + icc.exponent + static_data)
    return issuer.private(b"\x6A" + body + in_cert + h + b"\xBC"), remainder


def signed_static_data(issuer: RsaKey, static_data: bytes, dac: bytes = b"\xDA\xC1") -> bytes:
    pad = b"\xBB" * (issuer.size - 26)
    body = b"\x03\x01" + dac + pad
    return issuer.private(b"\x6A" + body + _sha1(body + static_data) + b"\xBC")


def signed_dynamic_data(icc: RsaKey, icc_dynamic_data: bytes, terminal_dynamic_data: bytes) -> bytes:
    ldd = len(icc_dynamic_data)
    pad = b"\xBB" * (icc.size - ldd - 25)
    body = b"\x05\x01" + bytes([ldd]) + icc_dynamic_data + pad
    return icc.private(b"\x6A" + body + _sha1(body + terminal_dynamic_data) + b"\xBC")
