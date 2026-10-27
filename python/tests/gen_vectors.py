"""Generate APDU-transcript conformance vectors for the C implementation.

Each vector holds the full configuration, the APDU exchange produced by the Python
reference kernel against the simulated card, and the expected outcome. The C test
replays the card responses and checks that it sends identical commands and reaches the
same outcome.

    python3 tests/gen_vectors.py ../conformance/vectors
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import scenarios as sc  # noqa: E402
from openpaykernel import AutoHost, ContactKernel, EntryPoint, MastercardKernel, OnlineResponse, TerminalConfig, \
    DiscoverKernel, UnionPayKernel, VisaKernel  # noqa: E402
from openpaykernel.config import AidConfig  # noqa: E402

REPORT_TAGS = [0x95, 0x9B, 0x9F34, 0x9F27, 0x8A, 0x9F66, 0x9F5B, 0x9F5D, 0x9F71]


def h(b: bytes) -> str:
    return b.hex().upper()


def emit_config(lines, env, txn, host=None):
    t = env.terminal
    lines.append(f"TERM type={t.terminal_type:02X} caps={h(t.capabilities)} addcaps={h(t.additional_capabilities)} "
                 f"country={h(t.country_code)}")
    for k in env.capks.keys.values():
        lines.append(f"CAPK rid={h(k.rid)} index={k.index:02X} exp={h(k.exponent)} expiry={k.expiry} "
                     f"mod={h(k.modulus)}")
    for a in env.aids:
        a: AidConfig
        parts = [f"aid={h(a.aid)}", f"kernel={a.kernel_id}", f"partial={int(a.partial_match)}",
                 f"floor={a.floor_limit}", f"tac_default={h(a.tac_default)}", f"tac_denial={h(a.tac_denial)}",
                 f"tac_online={h(a.tac_online)}", f"ttq={h(a.ttq)}", f"ddol={h(a.default_ddol)}",
                 f"version={h(a.app_version)}"]
        if a.cl_transaction_limit is not None:
            parts.append(f"cl_limit={a.cl_transaction_limit}")
        if a.cvm_required_limit is not None:
            parts.append(f"cvm_limit={a.cvm_required_limit}")
        if a.extra:
            parts.append("extra=" + ",".join(f"{t:X}:{h(v)}" for t, v in a.extra.items()))
        lines.append("AID " + " ".join(parts))
    lines.append(f"TXN amount={txn.amount} other={txn.amount_other} type={txn.type:02X} date={txn.date} "
                 f"time={txn.time} currency={h(txn.currency_code)} seq={txn.sequence_counter}")
    if host is not None:
        o = host.online
        lines.append(f"HOST pins={','.join(host.pins) if host.pins else '-'} online={int(o is not None)} "
                     f"approved={int(bool(o and o.approved))} arc={h(o.arc) if o else '-'} "
                     f"iad={h(o.issuer_auth_data) if o and o.issuer_auth_data else '-'} "
                     f"scripts={h(o.scripts) if o and o.scripts else '-'}")


class ScriptHost(AutoHost):
    def __init__(self, pins=("1234",), online=OnlineResponse(True, b"00")):
        super().__init__(None, online)
        self.pins = list(pins)
        self._it = iter(self.pins)
        self.online = online

    def enter_pin(self, online, tries):
        return next(self._it, None)

    def go_online(self, data):
        return self.online


def emit_result(lines, card, out, data):
    for c, r in card.log:
        lines.append(f"C {h(c)}")
        lines.append(f"R {h(r)}")
    lines.append(f"EXPECT status={int(out.status)} cvm={int(out.cvm)}")
    for t in REPORT_TAGS:
        if t in data:
            lines.append(f"EXPECT_TAG {t:X} {h(data[t])}")


def contactless(name, card, aids, txn):
    env = sc.env(aids)
    out = EntryPoint(env, [VisaKernel(), MastercardKernel(), UnionPayKernel(), DiscoverKernel()]).process(card, txn)
    lines = [f"SCENARIO {name}", "MODE contactless"]
    emit_config(lines, sc.env(aids), txn)
    emit_result(lines, card, out, out.data_record)
    return lines


def contact(name, card, txn, host, terminal=None):
    env = sc.env(sc.contact_aid_cfgs(), terminal)
    res = ContactKernel(env, host).process(card, txn)
    lines = [f"SCENARIO {name}", "MODE contact"]
    emit_config(lines, sc.env(sc.contact_aid_cfgs(), terminal), txn, host)
    emit_result(lines, card, res.outcome, res.data)
    return lines


def all_vectors():
    cda_term = TerminalConfig(capabilities=bytes.fromhex("E0F8E8"))
    scripts = bytes.fromhex("710F9F180400000001860684240000000A720F9F180400000002860684DA9F580101")
    yield contactless("visa_offline_approved", sc.visa_card(), [sc.visa_aid_cfg()], sc.txn(1000))
    yield contactless("visa_fdda_fail_online", sc.visa_card(corrupt_sdad=True, ctq=bytes.fromhex("2000")),
                      [sc.visa_aid_cfg()], sc.txn(1000))
    yield contactless("visa_online_pin", sc.visa_card(ctq=bytes.fromhex("8000"), decision="online"),
                      [sc.visa_aid_cfg()], sc.txn(4000))
    yield contactless("visa_see_phone", sc.visa_card(gpo_sw=0x6986), [sc.visa_aid_cfg()], sc.txn(100))
    yield contactless("mc_cda_approved", sc.mc_card(), [sc.mc_aid_cfg()], sc.txn(1000))
    yield contactless("mc_cda_fail", sc.mc_card(corrupt_sdad=True), [sc.mc_aid_cfg()], sc.txn(1000))
    yield contactless("mc_online_pin", sc.mc_card(), [sc.mc_aid_cfg()], sc.txn(15000))
    yield contactless("mc_cdcvm", sc.mc_card(aip=bytes.fromhex("1B80")), [sc.mc_aid_cfg()], sc.txn(40000))
    yield contactless("mc_two_brands_ppse", sc.mc_card(), [sc.visa_aid_cfg(), sc.mc_aid_cfg()], sc.txn(1000))
    yield contactless("upi_offline_approved", sc.upi_card(), [sc.upi_aid_cfg()], sc.txn(1000))
    yield contactless("upi_signature_online", sc.upi_card(ctq=bytes.fromhex("4000"), decision="online"),
                      [sc.upi_aid_cfg()], sc.txn(4000))
    yield contactless("upi_fdda_fail_declined", sc.upi_card(corrupt_sdad=True, ctq=bytes.fromhex("0000")),
                      [sc.upi_aid_cfg()], sc.txn(1000))
    yield contactless("discover_cda_approved", sc.discover_card(), [sc.discover_aid_cfg()], sc.txn(1000))
    yield contactless("discover_signature", sc.discover_card(), [sc.discover_aid_cfg()], sc.txn(4000))
    yield contactless("discover_online_pin", sc.discover_card(ctq=bytes.fromhex("8000")), [sc.discover_aid_cfg()],
                      sc.txn(4000))
    yield contactless("discover_cda_fail", sc.discover_card(corrupt_sdad=True), [sc.discover_aid_cfg()], sc.txn(1000))
    yield contactless("discover_cash_switch_interface", sc.discover_card(ctq=bytes.fromhex("0400")),
                      [sc.discover_aid_cfg()], sc.txn(1000, type=0x01))
    yield contactless("mc_gac_error_sw", sc.mc_card(gac_sw=0x6985), [sc.mc_aid_cfg()], sc.txn(1000))
    yield contactless("discover_gac_error_sw", sc.discover_card(gac_sw=0x6985), [sc.discover_aid_cfg()], sc.txn(1000))
    yield contact("contact_dda_offline_pin",
                  sc.contact_card(cvm_list=bytes.fromhex("000000000000000041031E031F03")), sc.txn(2000),
                  ScriptHost())
    yield contact("contact_wrong_pin_then_right",
                  sc.contact_card(cvm_list=bytes.fromhex("000000000000000001031F03")), sc.txn(2000),
                  ScriptHost(pins=("0000", "1234")))
    yield contact("contact_enciphered_pin", sc.contact_card(cvm_list=bytes.fromhex("000000000000000044031F03")),
                  sc.txn(2000), ScriptHost())
    yield contact("contact_online_scripts",
                  sc.contact_card(aip=bytes.fromhex("3C04"), cvm_list=bytes.fromhex("000000000000000042031F03")),
                  sc.txn(20000),
                  ScriptHost(online=OnlineResponse(True, b"00", bytes.fromhex("11223344556677883030"), scripts)))
    yield contact("contact_online_declined", sc.contact_card(), sc.txn(20000),
                  ScriptHost(online=OnlineResponse(False, b"05")))
    yield contact("contact_unable_online", sc.contact_card(), sc.txn(20000), ScriptHost(online=None))
    yield contact("contact_sda", sc.contact_card(aip=bytes.fromhex("5C00"), oda="sda"), sc.txn(2000), ScriptHost())
    yield contact("contact_cda", sc.contact_card(aip=bytes.fromhex("3D00"), oda="cda",
                                                 cvm_list=bytes.fromhex("000000000000000042031F03")),
                  sc.txn(20000), ScriptHost(), cda_term)
    yield contact("contact_cda_fail", sc.contact_card(aip=bytes.fromhex("3D00"), oda="cda", corrupt_sdad=True),
                  sc.txn(20000), ScriptHost(), cda_term)
    yield contact("contact_velocity_expired", sc.contact_card(expiry=bytes.fromhex("250101"), lcol=1, ucol=2),
                  sc.txn(100), ScriptHost())


def main(outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    names = []
    for lines in all_vectors():
        name = lines[0].split()[1]
        names.append(name)
        with open(os.path.join(outdir, name + ".txt"), "w") as f:
            f.write("\n".join(lines) + "\n")
    print(f"wrote {len(names)} vectors to {outdir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..", "conformance", "vectors"))
