"""ISO 7816-4 / EMV command APDUs and the reader abstraction."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from . import tlv


class Reader(Protocol):
    """Anything that can exchange an APDU with a card (PC/SC, NFC, a simulator)."""

    def transmit(self, capdu: bytes) -> bytes:  # returns data || SW1 SW2
        ...


class TransmissionError(IOError):
    """Raised by a Reader on a Level-1 error (timeout, collision, card removed)."""


@dataclass
class Response:
    data: bytes
    sw: int

    @property
    def ok(self) -> bool:
        return self.sw == 0x9000

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Response":
        if len(raw) < 2:
            raise TransmissionError("response shorter than SW1 SW2")
        return cls(raw[:-2], int.from_bytes(raw[-2:], "big"))


def _cmd(cla: int, ins: int, p1: int, p2: int, data: bytes | None = None, le: int | None = 0) -> bytes:
    out = bytes([cla, ins, p1, p2])
    if data:
        out += bytes([len(data)]) + data
    if le is not None:
        out += bytes([le])
    return out


def select(name: bytes, first: bool = True) -> bytes:
    return _cmd(0x00, 0xA4, 0x04, 0x00 if first else 0x02, name)


def read_record(sfi: int, record: int) -> bytes:
    return _cmd(0x00, 0xB2, record, (sfi << 3) | 0x04)


def get_processing_options(pdol_data: bytes) -> bytes:
    return _cmd(0x80, 0xA8, 0x00, 0x00, tlv.encode(0x83, pdol_data))


# Reference control parameter (P1) for GENERATE AC
AAC, TC, ARQC = 0x00, 0x40, 0x80
CDA_REQUESTED = 0x10


def generate_ac(ref_control: int, cdol_data: bytes) -> bytes:
    return _cmd(0x80, 0xAE, ref_control, 0x00, cdol_data)


def internal_authenticate(ddol_data: bytes) -> bytes:
    return _cmd(0x00, 0x88, 0x00, 0x00, ddol_data)


def get_data(tag: int) -> bytes:
    return _cmd(0x80, 0xCA, (tag >> 8) & 0xFF, tag & 0xFF)


def get_challenge() -> bytes:
    return _cmd(0x00, 0x84, 0x00, 0x00)


def verify(pin_block: bytes, qualifier: int = 0x80) -> bytes:
    """qualifier 0x80 = plaintext PIN, 0x88 = enciphered PIN."""
    return _cmd(0x00, 0x20, 0x00, qualifier, pin_block, le=None)


def external_authenticate(data: bytes) -> bytes:
    return _cmd(0x00, 0x82, 0x00, 0x00, data, le=None)


def compute_cryptographic_checksum(udol_data: bytes) -> bytes:
    return _cmd(0x80, 0x2A, 0x8E, 0x80, udol_data)


def plaintext_pin_block(pin: str) -> bytes:
    """ISO 9564 format 2 PIN block used by VERIFY with offline plaintext PIN."""
    if not 4 <= len(pin) <= 12 or not pin.isdigit():
        raise ValueError("PIN must be 4..12 digits")
    nibbles = f"2{len(pin):X}{pin}".ljust(16, "F")
    return bytes.fromhex(nibbles)


class Channel:
    """Wraps a Reader. It handles 61xx/6Cxx retries and keeps an APDU log."""

    def __init__(self, reader: Reader, log: list | None = None) -> None:
        self.reader = reader
        self.log = log if log is not None else []

    def exchange(self, capdu: bytes) -> Response:
        raw = self.reader.transmit(capdu)
        if len(raw) > 258:  # short APDU: at most 256 data bytes + SW1 SW2
            raise TransmissionError("response exceeds short APDU length")
        rsp = Response.from_bytes(raw)
        self.log.append((capdu, raw))
        if rsp.sw >> 8 == 0x61:  # more data available: GET RESPONSE
            raw = self.reader.transmit(bytes([0x00, 0xC0, 0x00, 0x00, rsp.sw & 0xFF]))
            self.log.append((b"GETRSP", raw))
            rsp = Response.from_bytes(raw)
        elif rsp.sw >> 8 == 0x6C:  # wrong Le: resend with the correct one
            raw = self.reader.transmit(capdu[:-1] + bytes([rsp.sw & 0xFF]))
            self.log.append((capdu, raw))
            rsp = Response.from_bytes(raw)
        return rsp
