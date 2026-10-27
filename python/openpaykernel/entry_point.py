"""Contactless Entry Point (EMV Contactless Book B)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from . import apdu, tlv
from .config import AidConfig, Environment, Transaction
from .outcome import (ErrorIndication, L1Error, L2Error, Message, Outcome, Start, Status, UIRequest,
                      end_application, try_another_interface)

PPSE = b"2PAY.SYS.DDF01"

# Kernels whose PDOL carries the Terminal Transaction Qualifiers (9F66) built at pre-processing
TTQ_KERNELS = (3, 6, 7)

KERNEL_DEFAULT_BY_RID = {
    bytes.fromhex("A000000004"): 2,  # Mastercard
    bytes.fromhex("A000000003"): 3,  # Visa
    bytes.fromhex("A000000025"): 4,  # American Express
    bytes.fromhex("A000000065"): 5,  # JCB
    bytes.fromhex("A000000152"): 6,  # Discover
    bytes.fromhex("A000000333"): 7,  # UnionPay
}


@dataclass
class Preprocessing:
    """Book B 3.1.1 Entry Point pre-processing indicators, kept per combination."""
    status_check: bool = False
    not_allowed: bool = False
    zero_amount: bool = False
    cvm_required_limit_exceeded: bool = False
    floor_limit_exceeded: bool = False
    cl_limit_exceeded: bool = False
    ttq: bytes | None = None


@dataclass
class Combination:
    aid_cfg: AidConfig
    kernel_id: int
    pre: Preprocessing = field(default_factory=Preprocessing)


@dataclass
class Candidate:
    adf_name: bytes
    kernel_id: int
    priority: int
    label: bytes
    combo: Combination
    extended_selection: bytes | None = None
    order: int = 0


@dataclass
class KernelContext:
    env: Environment
    txn: Transaction
    chan: apdu.Channel
    candidate: Candidate
    fci: bytes
    sw: int

    @property
    def aid_cfg(self) -> AidConfig:
        return self.candidate.combo.aid_cfg

    @property
    def pre(self) -> Preprocessing:
        return self.candidate.combo.pre


class ContactlessKernel(Protocol):
    kernel_id: int

    def start(self, ctx: KernelContext) -> Outcome:
        ...


def default_kernel_id(aid: bytes) -> int:
    return KERNEL_DEFAULT_BY_RID.get(aid[:5], 0)


def requested_kernel_id(kid: bytes | None, aid: bytes) -> int:
    """Book B 3.3.2.5: map Kernel Identifier (9F2A) to a kernel ID."""
    if not kid or kid[0] == 0:
        return default_kernel_id(aid)
    if kid[0] >> 6 in (0, 1):  # international kernel: short id in b6..b1
        return kid[0] & 0x3F
    # domestic/proprietary kernel: up to 3 bytes identify it
    return int.from_bytes(kid[:3], "big")


class EntryPoint:
    def __init__(self, env: Environment, kernels: list[ContactlessKernel]) -> None:
        self.env = env
        self.kernels = {k.kernel_id: k for k in kernels}
        self.combos: list[Combination] = []

    # --- Start A: pre-processing ---------------------------------------------------------
    def preprocess(self, txn: Transaction) -> Outcome | None:
        self.combos = []
        amount = txn.amount
        for cfg in self.env.aids:
            kid = cfg.kernel_id or default_kernel_id(cfg.aid)
            if kid not in self.kernels:
                continue
            p = Preprocessing()
            if cfg.status_check and amount == 10 ** txn.currency_exponent:  # one unit of currency
                p.status_check = True
            if amount == 0:
                if cfg.zero_amount_allowed:
                    p.zero_amount = True
                else:
                    p.not_allowed = True
            if cfg.cl_transaction_limit is not None and amount >= cfg.cl_transaction_limit:
                p.cl_limit_exceeded = True
                # kernels with an on-device CVM limit decide for themselves
                if cfg.cl_transaction_limit_cdcvm is None:
                    p.not_allowed = True
            if amount > cfg.floor_limit:
                p.floor_limit_exceeded = True
            if cfg.cvm_required_limit is not None and amount >= cfg.cvm_required_limit:
                p.cvm_required_limit_exceeded = True
            if kid in TTQ_KERNELS:
                ttq = bytearray(cfg.ttq)
                ttq[1] &= 0x3F  # clear 'online cryptogram required' and 'CVM required'
                if p.status_check or p.zero_amount or p.floor_limit_exceeded:
                    ttq[1] |= 0x80
                if p.cvm_required_limit_exceeded:
                    ttq[1] |= 0x40
                p.ttq = bytes(ttq)
            self.combos.append(Combination(cfg, kid, p))
        if not self.combos or all(c.pre.not_allowed for c in self.combos):
            return try_another_interface()
        return None

    # --- Start C: combination selection --------------------------------------------------
    def build_candidates(self, chan: apdu.Channel) -> tuple[list[Candidate], Outcome | None]:
        try:
            r = chan.exchange(apdu.select(PPSE))
        except apdu.TransmissionError:
            return [], Outcome(Status.TRY_AGAIN, start=Start.B,
                               error=ErrorIndication(l1=L1Error.TRANSMISSION),
                               ui_request=UIRequest(Message.PRESENT_CARD_AGAIN, "READY_TO_READ"))
        if not r.ok:
            return [], end_application(L2Error.NO_PPSE, r.sw, Message.INSERT_SWIPE_OR_TRY_ANOTHER)
        try:
            fci = tlv.parse(r.data)
        except tlv.TLVError:
            return [], end_application(L2Error.PPSE_FAULT, r.sw, Message.INSERT_SWIPE_OR_TRY_ANOTHER)
        top = fci[0] if fci and fci[0].tag == 0x6F else None
        bf0c = top.find(0xBF0C) if top else None
        if bf0c is None:
            return [], end_application(L2Error.PPSE_FAULT, r.sw, Message.INSERT_SWIPE_OR_TRY_ANOTHER)
        cands: list[Candidate] = []
        order = 0
        for entry in bf0c.children:
            if entry.tag != 0x61:
                continue
            adf = entry.find(0x4F)
            if adf is None or not 5 <= len(adf.value) <= 16:
                continue
            kid_tlv = entry.find(0x9F2A)
            kid = requested_kernel_id(kid_tlv.value if kid_tlv else None, adf.value)
            prio = entry.find(0x87)
            label = entry.find(0x50)
            ext = entry.find(0x9F29)
            for combo in self.combos:
                if combo.pre.not_allowed or combo.kernel_id != kid:
                    continue
                cfg = combo.aid_cfg
                if not (adf.value == cfg.aid or (cfg.partial_match and adf.value.startswith(cfg.aid))):
                    continue
                cands.append(Candidate(
                    adf.value, kid, (prio.value[0] & 0x0F) if prio and prio.value else 0,
                    label.value if label else b"", combo,
                    ext.value if ext and cfg.extended_selection_supported else None, order))
                order += 1
                break
        # Lower priority values are higher priority. 0 (none) goes last; ties keep PPSE order.
        cands.sort(key=lambda c: (c.priority == 0, c.priority, c.order))
        if not cands:
            return [], end_application(L2Error.EMPTY_CANDIDATE_LIST, 0, Message.INSERT_SWIPE_OR_TRY_ANOTHER)
        return cands, None

    # --- whole transaction ---------------------------------------------------------------
    def process(self, reader: apdu.Reader, txn: Transaction, log: list | None = None) -> Outcome:
        out = self.preprocess(txn)
        if out:
            return out
        chan = apdu.Channel(reader, log)
        cands, out = self.build_candidates(chan)
        if out:
            return out
        while cands:
            cand = cands.pop(0)
            name = cand.adf_name + (cand.extended_selection or b"")
            try:
                r = chan.exchange(apdu.select(name))
            except apdu.TransmissionError:
                return Outcome(Status.TRY_AGAIN, start=Start.B, error=ErrorIndication(l1=L1Error.TRANSMISSION))
            if not r.ok:
                continue
            kernel = self.kernels[cand.kernel_id]
            ctx = KernelContext(self.env, txn, chan, cand, r.data, r.sw)
            try:
                out = kernel.start(ctx)
            except apdu.TransmissionError:
                return Outcome(Status.TRY_AGAIN, start=Start.B, error=ErrorIndication(l1=L1Error.TRANSMISSION),
                               ui_request=UIRequest(Message.PRESENT_CARD_AGAIN, "READY_TO_READ"))
            if out.status == Status.SELECT_NEXT:
                continue
            return out
        return end_application(L2Error.EMPTY_CANDIDATE_LIST, 0, Message.INSERT_SWIPE_OR_TRY_ANOTHER)
