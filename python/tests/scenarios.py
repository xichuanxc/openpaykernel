"""Shared test scenarios. The C test-suite replays the same scenarios from generated vectors."""
from __future__ import annotations

from openpaykernel import AidConfig, CAPKStore, Environment, TerminalConfig, Transaction
from openpaykernel.sim.card import MASTERCARD_AID, VISA_AID, CardProfile, SimCard, test_keys

VISA_PDOL = bytes.fromhex("9F66049F02069F03069F1A0295055F2A029A039C019F3704")
MC_PDOL = bytes.fromhex("9F3501")


class CounterRng:
    """Deterministic RNG: returns consecutive byte values starting at seed. Mirrored in C."""

    def __init__(self, seed: int = 0x11) -> None:
        self.state = seed

    def __call__(self, n: int) -> bytes:
        out = bytes((self.state + i) & 0xFF for i in range(n))
        self.state = (self.state + n) & 0xFF
        return out


def capks() -> CAPKStore:
    store = CAPKStore()
    k = test_keys()
    store.add(k.capk(VISA_AID[:5]))
    store.add(k.capk(MASTERCARD_AID[:5]))
    return store


def visa_aid_cfg(**kw) -> AidConfig:
    base = dict(aid=VISA_AID[:5] + b"\x10\x10", kernel_id=3, floor_limit=10000, cl_transaction_limit=50000,
                cvm_required_limit=3000, ttq=bytes.fromhex("36004000"))
    base.update(kw)
    return AidConfig(**base)


def mc_aid_cfg(**kw) -> AidConfig:
    extra = {
        0xDF811B: b"\x20",                       # kernel config: on-device CVM supported
        0xDF811F: b"\x08",                       # security capability: CDA
        0xDF8118: b"\x60",                       # CVM required: online PIN + signature
        0xDF8119: b"\x08",                       # no CVM required
        0xDF8123: bytes.fromhex("000000010000"),  # reader floor limit 100.00
        0xDF8124: bytes.fromhex("000000030000"),  # CL limit no on-device CVM 300.00
        0xDF8125: bytes.fromhex("000000050000"),  # CL limit on-device CVM 500.00
        0xDF8126: bytes.fromhex("000000003000"),  # CVM required limit 30.00
        0xDF8120: bytes.fromhex("F45084800C"),    # TAC default
        0xDF8121: bytes.fromhex("0000000000"),    # TAC denial
        0xDF8122: bytes.fromhex("F45084800C"),    # TAC online
    }
    base = dict(aid=MASTERCARD_AID, kernel_id=2, extra=extra)
    base.update(kw)
    return AidConfig(**base)


def contact_aid_cfgs() -> list[AidConfig]:
    return [
        AidConfig(VISA_AID[:5] + b"\x10\x10", floor_limit=10000, tac_default=bytes.fromhex("DC4000A800"),
                  tac_denial=bytes.fromhex("0010000000"), tac_online=bytes.fromhex("DC4004F800"),
                  threshold=0, target_percent=0),
        AidConfig(MASTERCARD_AID, floor_limit=10000, tac_default=bytes.fromhex("FC50A8A000"),
                  tac_denial=bytes.fromhex("0000000000"), tac_online=bytes.fromhex("FC50A8F800")),
    ]


def env(aids, terminal: TerminalConfig | None = None) -> Environment:
    return Environment(terminal or TerminalConfig(), aids, capks(), CounterRng())


def visa_card(**kw) -> SimCard:
    base = dict(aid=VISA_AID, kind="visa", aip=bytes.fromhex("2000"), pdol=VISA_PDOL, ctq=bytes.fromhex("6000"),
                oda="dda", label=b"VISA CREDIT")
    base.update(kw)
    return SimCard(CardProfile(**base))


def mc_card(**kw) -> SimCard:
    base = dict(aid=MASTERCARD_AID, kind="mastercard", aip=bytes.fromhex("1980"), oda="cda", pdol=MC_PDOL,
                pan=bytes.fromhex("5413330089010012"), label=b"MASTERCARD",
                cvm_list=bytes.fromhex("000000000000000042031E031F03"))
    base.update(kw)
    return SimCard(CardProfile(**base))


def contact_card(**kw) -> SimCard:
    base = dict(aid=VISA_AID, kind="contact", aip=bytes.fromhex("3C00"), oda="dda")
    base.update(kw)
    return SimCard(CardProfile(**base))


def txn(amount: int, **kw) -> Transaction:
    return Transaction(amount=amount, **kw)
