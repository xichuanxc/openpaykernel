"""BER-TLV encoding as used by EMV (EMV Book 3, Annex B)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from .tags import is_terminal_source


class TLVError(ValueError):
    pass


def parse_tag(buf: bytes, pos: int = 0) -> tuple[int, int]:
    """Return (tag, new_pos). Tags are returned as integers, e.g. 0x9F02."""
    if pos >= len(buf):
        raise TLVError("truncated tag")
    first = buf[pos]
    tag = first
    pos += 1
    if first & 0x1F == 0x1F:
        while True:
            if pos >= len(buf):
                raise TLVError("truncated multi-byte tag")
            b = buf[pos]
            tag = (tag << 8) | b
            pos += 1
            if not b & 0x80:
                break
            if tag > 0xFFFFFFFF:
                raise TLVError("tag too long")
    return tag, pos


def parse_length(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise TLVError("truncated length")
    b = buf[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    n = b & 0x7F
    if n == 0 or n > 3:
        raise TLVError(f"unsupported length form 0x{b:02X}")
    if pos + n > len(buf):
        raise TLVError("truncated length")
    return int.from_bytes(buf[pos:pos + n], "big"), pos + n


def tag_bytes(tag: int) -> bytes:
    return tag.to_bytes((tag.bit_length() + 7) // 8 or 1, "big")


def tag_is_constructed(tag: int) -> bool:
    return bool(tag_bytes(tag)[0] & 0x20)


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82]) + n.to_bytes(2, "big")
    return bytes([0x83]) + n.to_bytes(3, "big")


def encode(tag: int, value: bytes) -> bytes:
    return tag_bytes(tag) + encode_length(len(value)) + value


@dataclass
class TLV:
    tag: int
    value: bytes
    children: list["TLV"] = field(default_factory=list)

    @property
    def constructed(self) -> bool:
        return tag_is_constructed(self.tag)

    def find(self, tag: int) -> "TLV | None":
        """Depth-first search of this node's subtree (excluding self)."""
        for c in self.children:
            if c.tag == tag:
                return c
            hit = c.find(tag)
            if hit is not None:
                return hit
        return None

    def encode(self) -> bytes:
        return encode(self.tag, self.value)

    def __repr__(self) -> str:
        return f"TLV({self.tag:X}, {self.value.hex().upper()})"


def iter_tlv(buf: bytes) -> Iterator[TLV]:
    """Iterate over top-level TLVs, recursing into constructed objects.

    Padding bytes 0x00 and 0xFF between objects are skipped (Book 3, B1).
    """
    pos = 0
    while pos < len(buf):
        if buf[pos] in (0x00, 0xFF):
            pos += 1
            continue
        tag, pos = parse_tag(buf, pos)
        length, pos = parse_length(buf, pos)
        if pos + length > len(buf):
            raise TLVError(f"value of tag {tag:X} overruns buffer")
        value = bytes(buf[pos:pos + length])
        pos += length
        node = TLV(tag, value)
        if node.constructed:
            node.children = list(iter_tlv(value))
        yield node


def parse(buf: bytes) -> list[TLV]:
    return list(iter_tlv(buf))


def find(buf_or_nodes, tag: int) -> TLV | None:
    nodes = parse(buf_or_nodes) if isinstance(buf_or_nodes, (bytes, bytearray)) else buf_or_nodes
    for n in nodes:
        if n.tag == tag:
            return n
        hit = n.find(tag)
        if hit is not None:
            return hit
    return None


def flatten(nodes: list[TLV]) -> Iterator[TLV]:
    """Yield every primitive TLV in a tree."""
    for n in nodes:
        if n.constructed:
            yield from flatten(n.children)
        else:
            yield n


def parse_tag_list(buf: bytes) -> list[int]:
    """Parse a list of tags without lengths (e.g. Tag 9F4A SDA Tag List)."""
    out, pos = [], 0
    while pos < len(buf):
        t, pos = parse_tag(buf, pos)
        out.append(t)
    return out


class TLVDatabase:
    """Flat tag → value store used by kernels (Book C-2 calls it the TLV Database)."""

    def __init__(self) -> None:
        self._d: dict[int, bytes] = {}

    def __contains__(self, tag: int) -> bool:
        return tag in self._d

    def __getitem__(self, tag: int) -> bytes:
        return self._d[tag]

    def __setitem__(self, tag: int, value: bytes) -> None:
        self._d[tag] = bytes(value)

    def get(self, tag: int, default: bytes | None = None) -> bytes | None:
        return self._d.get(tag, default)

    def pop(self, tag: int, default=None):
        return self._d.pop(tag, default)

    def present(self, tag: int) -> bool:
        return tag in self._d

    def not_empty(self, tag: int) -> bool:
        return bool(self._d.get(tag))

    def items(self):
        return self._d.items()

    def update(self, other: dict[int, bytes]) -> None:
        for k, v in other.items():
            self[k] = v

    def store_response(self, buf: bytes, *, overwrite: bool = True) -> list[int]:
        """Store all primitive tags in a card response. Returns stored tags in order."""
        stored = []
        for n in flatten(parse(buf)):
            if overwrite or n.tag not in self._d:
                self._d[n.tag] = n.value
            stored.append(n.tag)
        return stored

    def store_card_data(self, nodes: "list[TLV]") -> None:
        """Store the primitive TLVs of a card response. Terminal-sourced tags are ignored:
        a card must never be able to overwrite terminal data (Book 3 section 7, Book C-2 4.1)."""
        for n in flatten(nodes):
            if not is_terminal_source(n.tag):
                self._d[n.tag] = n.value

    def build(self, tags: list[int]) -> bytes:
        return b"".join(encode(t, self._d[t]) for t in tags if t in self._d)

    def copy(self) -> "TLVDatabase":
        db = TLVDatabase()
        db._d = dict(self._d)
        return db
