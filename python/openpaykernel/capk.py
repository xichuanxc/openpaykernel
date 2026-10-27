"""Certification Authority Public Keys (EMV Book 2, section 11.2.2) and revocation list."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CAPK:
    rid: bytes          # 5 bytes
    index: int          # tag 8F
    modulus: bytes
    exponent: bytes     # 0x03 or 0x010001
    expiry: str = "991231"  # YYMMDD
    hash_alg: int = 0x01    # SHA-1
    pk_alg: int = 0x01      # RSA
    checksum: bytes | None = None

    def computed_checksum(self) -> bytes:
        return hashlib.sha1(self.rid + bytes([self.index]) + self.modulus + self.exponent).digest()

    def verify(self) -> bool:
        return self.checksum is None or self.checksum == self.computed_checksum()

    @property
    def n(self) -> int:
        return int.from_bytes(self.modulus, "big")

    @property
    def e(self) -> int:
        return int.from_bytes(self.exponent, "big")


@dataclass
class CAPKStore:
    keys: dict[tuple[bytes, int], CAPK] = field(default_factory=dict)
    # Certificate revocation list: (rid, index, issuer certificate serial number)
    revoked: set[tuple[bytes, int, bytes]] = field(default_factory=set)

    def add(self, key: CAPK) -> None:
        if not key.verify():
            raise ValueError("CAPK checksum mismatch")
        self.keys[(key.rid, key.index)] = key

    def remove(self, rid: bytes, index: int) -> None:
        self.keys.pop((rid, index), None)

    def find(self, rid: bytes, index: int, today: str | None = None) -> CAPK | None:
        """today is YYMMDD. A key whose expiry has passed is treated as absent."""
        k = self.keys.get((rid, index))
        if k is None:
            return None
        if today is not None and _yymmdd_key(k.expiry) < _yymmdd_key(today):
            return None
        return k

    def revoke(self, rid: bytes, index: int, serial: bytes) -> None:
        self.revoked.add((rid, index, serial))

    def is_revoked(self, rid: bytes, index: int, serial: bytes) -> bool:
        return (rid, index, serial) in self.revoked

    def __len__(self) -> int:
        return len(self.keys)


def _yymmdd_key(d: str) -> str:
    """Map YYMMDD to a sortable YYYYMMDD. Book 4 century rule: YY < 50 → 20YY."""
    yy = int(d[:2])
    return f"{2000 + yy if yy < 50 else 1900 + yy}{d[2:]}"
