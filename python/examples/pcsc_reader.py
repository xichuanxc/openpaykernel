"""Run one transaction on real hardware through a PC/SC reader (contact or contactless).

    pip install pyscard
    python3 examples/pcsc_reader.py --amount 1.00                 # contactless (Entry Point)
    python3 examples/pcsc_reader.py --contact --amount 1.00       # contact chip
    python3 examples/pcsc_reader.py --capk-file my_test_capks.txt # enable offline data authentication

STUDY USE ONLY. Use EMV *test* cards. A live bank card's PIN try counter and transaction
counter (ATC) are real: a wrong PIN can block the card. Nothing is sent to a bank, and
"ONLINE REQUEST" is not an authorisation. See the Disclaimer in README.md.

The only hardware-specific code is the PcscReader class: one transmit() method that takes
a command APDU and returns response data + SW1 SW2. To port to another reader (vendor
SDK, serial/USB device, NFC controller), replace that class and keep the rest.
"""
from __future__ import annotations

import argparse
import datetime
import getpass
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openpaykernel import (CAPK, AidConfig, CAPKStore, ContactKernel, EntryPoint, Environment,  # noqa: E402
                           MastercardKernel, OnlineResponse, TerminalConfig, Transaction, UnionPayKernel,
                           VisaKernel, DiscoverKernel)
from openpaykernel.apdu import TransmissionError  # noqa: E402
from openpaykernel.tags import name  # noqa: E402


# --------------------------------------------------------------------------- hardware adapter
class PcscReader:
    """The ONLY hardware-specific part: transmit(C-APDU bytes) -> response data + SW1 SW2."""

    def __init__(self, index: int = 0) -> None:
        try:
            from smartcard.System import readers  # pyscard
        except ImportError:
            raise SystemExit("This example needs pyscard: pip install pyscard  (or: pip install .[pcsc])")

        available = readers()
        if not available:
            raise SystemExit("No PC/SC reader found. Is the reader plugged in and pcscd running?")
        if index >= len(available):
            raise SystemExit(f"Reader index {index} out of range: {[str(r) for r in available]}")
        self.name = str(available[index])
        self.connection = available[index].createConnection()
        self.connection.connect()  # powers / activates the card (Level 1)

    def transmit(self, capdu: bytes) -> bytes:
        try:
            data, sw1, sw2 = self.connection.transmit(list(capdu))
        except Exception as exc:  # card removed, timeout, communication error
            raise TransmissionError(str(exc)) from exc
        return bytes(data) + bytes([sw1, sw2])


# --------------------------------------------------------------------------- configuration
VISA = bytes.fromhex("A0000000031010")
MASTERCARD = bytes.fromhex("A0000000041010")
DISCOVER = bytes.fromhex("A0000001523010")
UNIONPAY = bytes.fromhex("A0000003330101")  # partial match: 010101 debit, 010102 credit, 010103 quasi-credit


def build_environment(capk_file: str | None) -> Environment:
    mc_kernel_config = {
        0xDF811B: b"\x20", 0xDF811F: b"\x08", 0xDF8118: b"\x60", 0xDF8119: b"\x08",
        0xDF8123: bytes.fromhex("000000010000"), 0xDF8124: bytes.fromhex("000000030000"),
        0xDF8125: bytes.fromhex("000000050000"), 0xDF8126: bytes.fromhex("000000003000"),
        0xDF8120: bytes.fromhex("F45084800C"), 0xDF8121: bytes.fromhex("0000000000"),
        0xDF8122: bytes.fromhex("F45084800C"),
    }
    aids = [
        AidConfig(VISA, kernel_id=3, floor_limit=10000, cl_transaction_limit=50000, cvm_required_limit=3000,
                  tac_default=bytes.fromhex("DC4000A800"), tac_denial=bytes.fromhex("0010000000"),
                  tac_online=bytes.fromhex("DC4004F800")),
        AidConfig(UNIONPAY, kernel_id=7, floor_limit=10000, cl_transaction_limit=50000, cvm_required_limit=3000,
                  tac_default=bytes.fromhex("D84000A800"), tac_denial=bytes.fromhex("0010000000"),
                  tac_online=bytes.fromhex("D84004F800")),
        AidConfig(DISCOVER, kernel_id=6, floor_limit=10000, cl_transaction_limit=50000, cvm_required_limit=3000,
                  tac_default=bytes.fromhex("DC4000A800"), tac_denial=bytes.fromhex("0010000000"),
                  tac_online=bytes.fromhex("DC4004F800")),
        AidConfig(MASTERCARD, kernel_id=2, floor_limit=10000, extra=mc_kernel_config,
                  tac_default=bytes.fromhex("FC50A8A000"), tac_denial=bytes.fromhex("0000000000"),
                  tac_online=bytes.fromhex("FC50A8F800")),
    ]
    return Environment(TerminalConfig(), aids, load_capks(capk_file))


def load_capks(path: str | None) -> CAPKStore:
    """Text file, one key per line: RID INDEX EXPONENT MODULUS [EXPIRY_YYMMDD] (hex)."""
    store = CAPKStore()
    if not path:
        print("note: no --capk-file given, so offline data authentication will fail (expected).")
        return store
    with open(path) as f:
        for line in f:
            parts = line.split()
            if not parts or parts[0].startswith("#"):
                continue
            rid, index, exp, mod = parts[:4]
            expiry = parts[4] if len(parts) > 4 else "491231"
            store.add(CAPK(bytes.fromhex(rid), int(index, 16), bytes.fromhex(mod), bytes.fromhex(exp), expiry))
    print(f"loaded {len(store)} CA public keys")
    return store


class ConsoleHost:
    """Contact-kernel callbacks answered from the keyboard (study use: PIN is not protected)."""

    def choose_application(self, candidates):
        for i, c in enumerate(candidates):
            print(f"  [{i}] {c.label}  ({c.aid.hex().upper()})")
        choice = input("select application [0]: ").strip()
        return int(choice) if choice.isdigit() else 0

    def enter_pin(self, online, tries_left):
        kind = "online" if online else f"offline (tries left: {tries_left})"
        pin = getpass.getpass(f"enter {kind} PIN, empty to bypass: ")
        return pin or None

    def go_online(self, data):
        print("online authorisation request (field 55):")
        for tag, value in data.items():
            print(f"  {tag:>6X} {value.hex().upper()}")
        answer = input("simulate issuer response: [a]pprove / [d]ecline / [u]nable to go online: ").strip().lower()
        if answer.startswith("u"):
            return None
        return OnlineResponse(answer.startswith("a"), b"00" if answer.startswith("a") else b"05")


# --------------------------------------------------------------------------- run
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--amount", default="1.00", help="amount in major units, e.g. 12.50")
    ap.add_argument("--contact", action="store_true", help="contact chip instead of contactless")
    ap.add_argument("--reader", type=int, default=0, help="PC/SC reader index")
    ap.add_argument("--capk-file", help="CA public keys for offline data authentication")
    args = ap.parse_args()

    now = datetime.datetime.now()
    txn = Transaction(amount=round(float(args.amount) * 100), date=now.strftime("%y%m%d"),
                      time=now.strftime("%H%M%S"))
    env = build_environment(args.capk_file)
    reader = PcscReader(args.reader)
    print(f"reader: {reader.name}")

    log: list = []
    if args.contact:
        result = ContactKernel(env, ConsoleHost()).process(reader, txn, log)
        outcome, data = result.outcome, result.data
    else:
        outcome = EntryPoint(env, [VisaKernel(), MastercardKernel(), UnionPayKernel(), DiscoverKernel()]).process(
            reader, txn, log)
        data = outcome.data_record

    print("\nAPDU trace:")
    for capdu, rapdu in log:
        print(f"  > {capdu.hex().upper()}\n  < {rapdu.hex().upper()}")
    print(f"\noutcome: {outcome.status.name}   CVM: {outcome.cvm.name}   L2 error: {outcome.error.l2.name}")
    for tag in (0x95, 0x9B, 0x9F34, 0x9F27, 0x9F26, 0x8A):
        if tag in data:
            print(f"  {tag:>6X} {name(tag):<34} {data[tag].hex().upper()}")


if __name__ == "__main__":
    main()
