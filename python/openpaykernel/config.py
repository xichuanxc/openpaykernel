"""Terminal, application (AID) and transaction parameters."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable

from .capk import CAPKStore


@dataclass
class TerminalConfig:
    country_code: bytes = bytes.fromhex("0840")          # 9F1A
    terminal_type: int = 0x22                            # 9F35: attended, offline with online capability
    capabilities: bytes = bytes.fromhex("E0F8C8")        # 9F33
    additional_capabilities: bytes = bytes.fromhex("6000F0A001")  # 9F40
    terminal_id: bytes = b"TERM0001"                     # 9F1C
    ifd_serial: bytes = b"00000001"                      # 9F1E
    merchant_category_code: bytes = bytes.fromhex("5411")  # 9F15
    merchant_id: bytes = b"MERCHANT0000001"              # 9F16
    merchant_name_location: bytes = b"OPEN L2 TEST SHOP"  # 9F4E
    exception_file: set[bytes] = field(default_factory=set)  # hot-listed PANs (hex string bytes, no F padding)

    @property
    def online_capable(self) -> bool:
        return (self.terminal_type & 0x0F) in (1, 2, 4, 5)

    @property
    def offline_only(self) -> bool:
        return (self.terminal_type & 0x0F) in (3, 6)

    @property
    def attended(self) -> bool:
        return (self.terminal_type & 0x0F) <= 3

    def tags(self) -> dict[int, bytes]:
        return {
            0x9F1A: self.country_code,
            0x9F35: bytes([self.terminal_type]),
            0x9F33: self.capabilities,
            0x9F40: self.additional_capabilities,
            0x9F1C: self.terminal_id,
            0x9F1E: self.ifd_serial,
            0x9F15: self.merchant_category_code,
            0x9F16: self.merchant_id,
            0x9F4E: self.merchant_name_location,
        }


@dataclass
class AidConfig:
    aid: bytes
    kernel_id: int = 0               # 0 = derive from RID
    partial_match: bool = True       # Application Selection Indicator
    app_version: bytes = bytes.fromhex("0002")  # 9F09
    tac_default: bytes = bytes.fromhex("0000000000")
    tac_denial: bytes = bytes.fromhex("0000000000")
    tac_online: bytes = bytes.fromhex("0000000000")
    floor_limit: int = 0             # minor units (contact 9F1B, contactless reader floor limit)
    cl_transaction_limit: int | None = None   # contactless: amount must be below
    cl_transaction_limit_cdcvm: int | None = None
    cvm_required_limit: int | None = None
    threshold: int = 0               # random transaction selection
    target_percent: int = 0
    max_target_percent: int = 0
    default_ddol: bytes = bytes.fromhex("9F3704")
    default_tdol: bytes = b""
    ttq: bytes = bytes.fromhex("36004000")     # Visa 9F66 base value
    status_check: bool = False
    zero_amount_allowed: bool = True
    extended_selection_supported: bool = False
    extra: dict[int, bytes] = field(default_factory=dict)  # kernel-specific TLVs (e.g. DF81xx)


@dataclass
class Transaction:
    amount: int                      # minor units
    currency_code: bytes = bytes.fromhex("0840")
    currency_exponent: int = 2
    type: int = 0x00                 # 9C: 00 purchase, 01 cash, 09 cashback, 20 refund
    amount_other: int = 0
    date: str = "261027"             # YYMMDD
    time: str = "120000"             # HHMMSS
    sequence_counter: int = 1
    force_online: bool = False

    def tags(self) -> dict[int, bytes]:
        return {
            0x9F02: bcd(self.amount, 6),
            0x9F03: bcd(self.amount_other, 6),
            0x81: self.amount.to_bytes(4, "big"),
            0x9F04: self.amount_other.to_bytes(4, "big"),
            0x5F2A: self.currency_code,
            0x5F36: bytes([self.currency_exponent]),
            0x9C: bytes([self.type]),
            0x9A: bytes.fromhex(self.date),
            0x9F21: bytes.fromhex(self.time),
            0x9F41: bcd(self.sequence_counter, 4),
        }


def bcd(n: int, length: int) -> bytes:
    return bytes.fromhex(str(n).rjust(length * 2, "0"))


def bcd_to_int(b: bytes) -> int:
    s = b.hex()
    return int(s) if s.isdigit() else 0


@dataclass
class Environment:
    """Everything a kernel needs besides the card: config, keys and the RNG."""
    terminal: TerminalConfig
    aids: list[AidConfig]
    capks: CAPKStore = field(default_factory=CAPKStore)
    rng: Callable[[int], bytes] = os.urandom

    def aid_config(self, aid: bytes) -> AidConfig | None:
        best = None
        for c in self.aids:
            if aid == c.aid or (c.partial_match and aid.startswith(c.aid)):
                if best is None or len(c.aid) > len(best.aid):
                    best = c
        return best


class Bits:
    """A byte string with Book 3 style 1-based (byte, bit) addressing, used for TVR, TSI and so on."""

    def __init__(self, n: int, init: bytes | None = None) -> None:
        self.b = bytearray(init if init is not None else bytes(n))

    def set(self, byte: int, bit: int, on: bool = True) -> None:
        mask = 1 << (bit - 1)
        if on:
            self.b[byte - 1] |= mask
        else:
            self.b[byte - 1] &= ~mask & 0xFF

    def get(self, byte: int, bit: int) -> bool:
        return bool(self.b[byte - 1] & (1 << (bit - 1)))

    def __bytes__(self) -> bytes:
        return bytes(self.b)

    def hex(self) -> str:
        return self.b.hex().upper()


def bit(data: bytes | None, byte: int, b: int) -> bool:
    return bool(data and len(data) >= byte and data[byte - 1] & (1 << (b - 1)))
