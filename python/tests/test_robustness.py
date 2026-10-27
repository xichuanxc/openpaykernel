"""Corrupted card responses must lead to an Outcome, never to an unhandled exception."""
import random

from openpaykernel import (AmexKernel, AutoHost, ContactKernel, DiscoverKernel, EntryPoint, MastercardKernel, UnionPayKernel,
                           VisaKernel)
from openpaykernel.outcome import Outcome

import scenarios as sc


class Mutating:
    def __init__(self, card, seed):
        self.card = card
        self.rnd = random.Random(seed)

    def transmit(self, c):
        r = bytearray(self.card.transmit(c))
        for _ in range(self.rnd.randrange(4)):
            if len(r) > 2:
                r[self.rnd.randrange(len(r) - 2)] ^= 1 << self.rnd.randrange(8)
        if len(r) > 3 and self.rnd.random() < 0.1:
            cut = self.rnd.randrange(len(r) - 2)
            r = r[:cut] + r[-2:]
        return bytes(r)


def test_contactless_survives_corruption():
    for seed in range(300):
        card = [sc.mc_card, sc.visa_card, sc.upi_card, sc.discover_card, sc.amex_card][seed % 5]()
        ep = EntryPoint(sc.env([sc.visa_aid_cfg(), sc.mc_aid_cfg(), sc.upi_aid_cfg(), sc.discover_aid_cfg(),
                                sc.amex_aid_cfg()]),
                        [VisaKernel(), MastercardKernel(), UnionPayKernel(), DiscoverKernel(), AmexKernel()])
        assert isinstance(ep.process(Mutating(card, seed), sc.txn(1000 + seed)), Outcome)


def test_contact_survives_corruption():
    for seed in range(300):
        card = sc.contact_card(oda=["sda", "dda", "cda"][seed % 3], aip=bytes.fromhex(["5C00", "3C00", "3D00"][seed % 3]))
        res = ContactKernel(sc.env(sc.contact_aid_cfgs()), AutoHost()).process(Mutating(card, seed),
                                                                                sc.txn(2000 + seed * 50))
        assert isinstance(res.outcome, Outcome)
