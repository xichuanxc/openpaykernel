"""Data Object List handling (EMV Book 3, section 5.4)."""
from __future__ import annotations

from typing import Callable, Mapping

from . import tags as _tags
from .tlv import parse_length, parse_tag


def parse_dol(dol: bytes) -> list[tuple[int, int]]:
    """Return [(tag, length), ...]."""
    out, pos = [], 0
    while pos < len(dol):
        tag, pos = parse_tag(dol, pos)
        length, pos = parse_length(dol, pos)
        out.append((tag, length))
    return out


def fit(value: bytes, length: int, fmt: str) -> bytes:
    """Pad or truncate a value to a DOL entry length following Book 3 5.4 rules."""
    n = len(value)
    if n == length:
        return value
    if fmt == "n":
        # numeric: right-justified, leading zeros; truncate leftmost bytes
        return value[-length:] if n > length else bytes(length - n) + value
    if fmt == "cn":
        # compressed numeric: left-justified, trailing 'F' nibbles
        return value[:length] if n > length else value + b"\xFF" * (length - n)
    # an / ans / b: left-justified, trailing zeros (binary) / truncate right
    return value[:length] if n > length else value + bytes(length - n)


def build_dol(dol: bytes, lookup: Mapping[int, bytes] | Callable[[int], bytes | None]) -> bytes:
    """Concatenate the values requested by a DOL.

    Missing data and constructed tags are filled with zeros, as Book 3 requires.
    """
    get = lookup if callable(lookup) else lookup.get
    out = bytearray()
    for tag, length in parse_dol(dol):
        v = get(tag)
        if v is None or (_first_byte(tag) & 0x20):
            out += bytes(length)
        else:
            out += fit(v, length, _tags.fmt(tag))
    return bytes(out)


def dol_tags(dol: bytes) -> list[int]:
    return [t for t, _ in parse_dol(dol)]


def _first_byte(tag: int) -> int:
    return tag >> (8 * ((tag.bit_length() - 1) // 8)) if tag else 0
