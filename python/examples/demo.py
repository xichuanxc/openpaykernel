"""Run a contactless and a contact transaction against the simulated card and print the outcome.

    cd python && python3 examples/demo.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

import scenarios as sc  # noqa: E402
from openpaykernel import AutoHost, ContactKernel, EntryPoint, MastercardKernel, OnlineResponse, VisaKernel  # noqa: E402
from openpaykernel.tags import name  # noqa: E402


def show(title, outcome, data, log):
    print(f"\n=== {title} ===")
    for c, r in log:
        print(f"  > {c.hex().upper()}")
        print(f"  < {r.hex().upper()[:96]}{'...' if len(r) > 48 else ''}")
    print(f"  outcome: {outcome.status.name}  CVM: {outcome.cvm.name}")
    for tag in (0x95, 0x9F34, 0x9F27, 0x9F26, 0x8A):
        if tag in data:
            print(f"  {tag:>6X} {name(tag):<34} {data[tag].hex().upper()}")


if __name__ == "__main__":
    ep = EntryPoint(sc.env([sc.visa_aid_cfg(), sc.mc_aid_cfg()]), [VisaKernel(), MastercardKernel()])
    card = sc.visa_card()
    out = ep.process(card, sc.txn(1250))
    show("Visa qVSDC, 12.50, offline approved with fDDA", out, out.data_record, card.log)

    card = sc.mc_card()
    out = ep.process(card, sc.txn(15000))
    show("Mastercard, 150.00 above floor limit, CDA + online PIN", out, out.data_record, card.log)

    card = sc.contact_card(aip=bytes.fromhex("3C04"), cvm_list=bytes.fromhex("000000000000000041031F03"))
    kernel = ContactKernel(sc.env(sc.contact_aid_cfgs()), AutoHost("1234", OnlineResponse(True, b"00")))
    res = kernel.process(card, sc.txn(20000))
    show("Contact chip, 200.00, offline PIN + online authorisation", res.outcome, res.data, card.log)
