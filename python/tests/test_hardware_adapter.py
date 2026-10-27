"""The PC/SC example adapter (examples/pcsc_reader.py) works against a fake pyscard backend.

This checks the documented hardware integration path without real hardware: pyscard's
connection.transmit() takes a list of ints and returns (data, sw1, sw2).
"""
import importlib.util
import os
import sys
import types

import pytest

from openpaykernel import ContactKernel, EntryPoint, MastercardKernel, VisaKernel
from openpaykernel.apdu import TransmissionError
from openpaykernel.outcome import Status

import scenarios as sc

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "pcsc_reader.py")


class FakeConnection:
    def __init__(self, card, fail_after=None):
        self.card, self.n, self.fail_after = card, 0, fail_after

    def connect(self):
        pass

    def transmit(self, apdu_list):
        assert isinstance(apdu_list, list) and all(isinstance(b, int) for b in apdu_list)
        self.n += 1
        if self.fail_after is not None and self.n > self.fail_after:
            raise RuntimeError("card removed")
        raw = self.card.transmit(bytes(apdu_list))
        return list(raw[:-2]), raw[-2], raw[-1]


class FakeReader:
    def __init__(self, conn):
        self.conn = conn

    def createConnection(self):
        return self.conn

    def __str__(self):
        return "Fake PC/SC Reader 0"


@pytest.fixture
def pcsc(monkeypatch):
    """Load the example with a fake `smartcard` package and return a factory for PcscReader."""
    holder = {}
    smartcard = types.ModuleType("smartcard")
    system = types.ModuleType("smartcard.System")
    system.readers = lambda: [holder["reader"]]
    smartcard.System = system
    monkeypatch.setitem(sys.modules, "smartcard", smartcard)
    monkeypatch.setitem(sys.modules, "smartcard.System", system)
    spec = importlib.util.spec_from_file_location("pcsc_reader_example", EXAMPLE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def make(card, fail_after=None):
        holder["reader"] = FakeReader(FakeConnection(card, fail_after))
        return mod.PcscReader(0)

    return make


def test_pcsc_adapter_contactless(pcsc):
    reader = pcsc(sc.visa_card())
    ep = EntryPoint(sc.env([sc.visa_aid_cfg()]), [VisaKernel(), MastercardKernel()])
    assert ep.process(reader, sc.txn(1000)).status == Status.APPROVED


def test_pcsc_adapter_contact(pcsc):
    reader = pcsc(sc.contact_card(cvm_list=bytes.fromhex("000000000000000041031F03")))
    from openpaykernel import AutoHost
    res = ContactKernel(sc.env(sc.contact_aid_cfgs()), AutoHost()).process(reader, sc.txn(2000))
    assert res.outcome.status == Status.APPROVED


def test_pcsc_adapter_card_removed_maps_to_try_again(pcsc):
    reader = pcsc(sc.visa_card(), fail_after=3)
    with pytest.raises(TransmissionError):
        for _ in range(5):
            reader.transmit(bytes.fromhex("00A404000E325041592E5359532E444446303100"))
    reader = pcsc(sc.visa_card(), fail_after=3)
    out = EntryPoint(sc.env([sc.visa_aid_cfg()]), [VisaKernel(), MastercardKernel()]).process(reader, sc.txn(1000))
    assert out.status == Status.TRY_AGAIN  # Level-1 error → present card again


def test_pcsc_adapter_card_removed_contact(pcsc):
    from openpaykernel import AutoHost
    from openpaykernel.outcome import L1Error
    reader = pcsc(sc.contact_card(), fail_after=4)
    res = ContactKernel(sc.env(sc.contact_aid_cfgs()), AutoHost()).process(reader, sc.txn(2000))
    assert res.outcome.status == Status.END_APPLICATION
    assert res.outcome.error.l1 == L1Error.TRANSMISSION
