"""Shared test scenarios. The C test-suite replays the same scenarios from generated vectors."""
from __future__ import annotations

from openpaykernel import AidConfig, CAPKStore, Environment, TerminalConfig, Transaction
from openpaykernel.sim.card import AMEX_AID, DISCOVER_AID, JCB_AID, MASTERCARD_AID, UNIONPAY_AID, VISA_AID, CardProfile, SimCard, test_keys

VISA_PDOL = bytes.fromhex("9F66049F02069F03069F1A0295055F2A029A039C019F3704")
MC_PDOL = bytes.fromhex("9F3501")
JCB_PDOL = bytes.fromhex("9F35019F53039F02069F37045F2A029A039C019F1A02")
AMEX_PDOL = bytes.fromhex("9F35019F6E049F02069F37045F2A029A039C019F1A02")


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
    store.add(k.capk(UNIONPAY_AID[:5]))
    store.add(k.capk(DISCOVER_AID[:5]))
    store.add(k.capk(AMEX_AID[:5]))
    store.add(k.capk(JCB_AID[:5]))
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


def upi_aid_cfg(**kw) -> AidConfig:
    base = dict(aid=UNIONPAY_AID[:7], kernel_id=7, floor_limit=10000, cl_transaction_limit=50000,
                cvm_required_limit=3000, ttq=bytes.fromhex("36004000"))
    base.update(kw)
    return AidConfig(**base)


def discover_aid_cfg(**kw) -> AidConfig:
    base = dict(aid=DISCOVER_AID, kernel_id=6, floor_limit=10000, cl_transaction_limit=50000,
                cvm_required_limit=3000, ttq=bytes.fromhex("36004000"),
                tac_default=bytes.fromhex("DC4000A800"), tac_denial=bytes.fromhex("0010000000"),
                tac_online=bytes.fromhex("DC4004F800"))
    base.update(kw)
    return AidConfig(**base)


def amex_aid_cfg(**kw) -> AidConfig:
    base = dict(aid=AMEX_AID, kernel_id=4, floor_limit=10000, cl_transaction_limit=50000, cvm_required_limit=3000,
                tac_default=bytes.fromhex("DC50FC9800"), tac_denial=bytes.fromhex("0010000000"),
                tac_online=bytes.fromhex("DE00FC9800"), extra={0x9F6E: bytes.fromhex("D8E00003")})
    base.update(kw)
    return AidConfig(**base)


def jcb_aid_cfg(**kw) -> AidConfig:
    base = dict(aid=JCB_AID, kernel_id=5, floor_limit=10000, cl_transaction_limit=50000, cvm_required_limit=3000,
                tac_default=bytes.fromhex("FC6024A800"), tac_denial=bytes.fromhex("0010000000"),
                tac_online=bytes.fromhex("FC60ACF800"), extra={0x9F53: bytes.fromhex("720000")})
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


def upi_card(**kw) -> SimCard:
    base = dict(aid=UNIONPAY_AID, kind="unionpay", aip=bytes.fromhex("2000"), pdol=VISA_PDOL,
                ctq=bytes.fromhex("6000"), oda="dda", label=b"UNIONPAY", pan=bytes.fromhex("6250947000000014"))
    base.update(kw)
    return SimCard(CardProfile(**base))


def discover_card(**kw) -> SimCard:
    base = dict(aid=DISCOVER_AID, kind="discover", aip=bytes.fromhex("1981"), oda="cda", pdol=VISA_PDOL,
                ctq=bytes.fromhex("4000"), pan=bytes.fromhex("6510000000001250"), label=b"DISCOVER",
                cvm_list=bytes.fromhex("000000000000000042031E031F03"))
    base.update(kw)
    return SimCard(CardProfile(**base))


def amex_card(**kw) -> SimCard:
    base = dict(aid=AMEX_AID, kind="amex", aip=bytes.fromhex("1981"), oda="cda", pdol=AMEX_PDOL,
                pan=bytes.fromhex("374245455400126F"), label=b"AMERICAN EXPRESS",
                cvm_list=bytes.fromhex("000000000000000042031E031F03"))
    base.update(kw)
    return SimCard(CardProfile(**base))


def jcb_card(**kw) -> SimCard:
    base = dict(aid=JCB_AID, kind="jcb", aip=bytes.fromhex("1981"), oda="cda", pdol=JCB_PDOL,
                pan=bytes.fromhex("3566002020360505"), label=b"JCB",
                cvm_list=bytes.fromhex("000000000000000042031E031F03"))
    base.update(kw)
    return SimCard(CardProfile(**base))


def contact_card(**kw) -> SimCard:
    base = dict(aid=VISA_AID, kind="contact", aip=bytes.fromhex("3C00"), oda="dda")
    base.update(kw)
    return SimCard(CardProfile(**base))


def txn(amount: int, **kw) -> Transaction:
    return Transaction(amount=amount, **kw)
