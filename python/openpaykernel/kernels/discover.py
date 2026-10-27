"""Kernel 6: Discover D-PAS (EMV Contactless Book C-6), EMV mode.

Flow: TTQ (9F66) in the PDOL → GET PROCESSING OPTIONS returns AIP, AFL and the Card
Processing Requirements (CPR, 9F71) → READ RECORD → interface-switch rules from the CPR →
CDA selection → processing restrictions → CVM from TTQ + CPR → floor limit → terminal
action analysis → GENERATE AC (CDA) → outcome.

The CPR plays the role of Visa's CTQ. Bits used here (byte, bit):
  (1,8) online PIN required          (1,7) signature required
  (1,3) switch interface for cash     (1,2) switch interface for cashback
  (2,8) consumer device CVM performed

Not implemented: D-PAS mag-stripe (legacy) mode, Issuer Update Processing, data storage.
These bit assignments follow the public structure of Book C-6 but have NOT been verified
against the official specification text.
"""
from __future__ import annotations

from .. import apdu, tlv
from ..config import bit
from ..emvproc import (TVR_FLOOR_LIMIT, CardError, Session, check_mandatory, parse_gpo_response,
                       processing_restrictions, read_application_data, terminal_action_analysis)
from ..entry_point import KernelContext
from ..outcome import (CVM, L2Error, Message, Outcome, Start, Status, UIRequest, end_application, select_next,
                       try_another_interface)
from . import common

DATA_RECORD_TAGS = [0x9F02, 0x9F03, 0x9F26, 0x9F27, 0x9F36, 0x9F10, 0x9F37, 0x95, 0x9A, 0x9C, 0x5F2A, 0x82,
                    0x9F1A, 0x9F33, 0x9F34, 0x9F35, 0x9F66, 0x9F71, 0x5A, 0x5F34, 0x57, 0x5F24, 0x84, 0x9F06]

# CVM Results (9F34) reported for each decision (method, condition, result)
CVM_RESULTS = {
    CVM.NO_CVM: bytes.fromhex("3F0000"),
    CVM.ONLINE_PIN: bytes.fromhex("420300"),
    CVM.SIGNATURE: bytes.fromhex("1E0300"),
    CVM.CONFIRMATION_CODE_VERIFIED: bytes.fromhex("010002"),
}


class DiscoverKernel:
    kernel_id = 6

    def start(self, ctx: KernelContext) -> Outcome:
        s = Session.new(ctx.env, ctx.aid_cfg, ctx.txn, ctx.chan)
        try:
            return self._run(ctx, s)
        except common.StatusWordError as e:
            return end_application(L2Error.STATUS_BYTES, e.sw, Message.PROCESSING_ERROR)
        except CardError as e:
            return end_application(L2Error.CARD_DATA_ERROR, e.sw, Message.PROCESSING_ERROR)
        except tlv.TLVError:
            return end_application(L2Error.PARSING_ERROR, msg=Message.PROCESSING_ERROR)

    def _run(self, ctx: KernelContext, s: Session) -> Outcome:
        db, cfg = s.db, ctx.aid_cfg
        if not common.store_fci(s, ctx.fci, ctx.candidate.adf_name):
            return select_next(L2Error.PARSING_ERROR)
        ttq = ctx.pre.ttq or cfg.ttq
        db[0x9F66] = ttq

        # GET PROCESSING OPTIONS
        s.pdol_data = s.build_dol(db.get(0x9F38, b""))
        r = s.chan.exchange(apdu.get_processing_options(s.pdol_data))
        if r.sw == 0x6984:
            return try_another_interface()
        if r.sw == 0x6986:
            return Outcome(Status.TRY_AGAIN, start=Start.B, field_off_request_ms=1300,
                           ui_request=UIRequest(Message.SEE_PHONE, "PROCESSING", hold_time_ms=1300))
        if not r.ok:
            return select_next(L2Error.STATUS_BYTES, r.sw)
        parse_gpo_response(r.data, db)
        aip, cpr = db[0x82], db.get(0x9F71)
        if not db.get(0x94):
            # without an AFL the card only offers mag-stripe mode, which is not implemented
            return end_application(L2Error.MAGSTRIPE_NOT_SUPPORTED, msg=Message.INSERT_SWIPE_OR_TRY_ANOTHER)

        read_application_data(s)
        check_mandatory(s, [0x5F24, 0x5A, 0x8C])

        # Interface switching requested by the card
        is_cash = s.txn.type in (0x01, 0x17)
        is_cashback = s.txn.type == 0x09 or s.txn.amount_other > 0
        if (is_cash and bit(cpr, 1, 3)) or (is_cashback and bit(cpr, 1, 2)):
            return try_another_interface()

        cda = common.select_cda(s, aip, bit(s.env.terminal.capabilities, 3, 4))
        processing_restrictions(s)

        cvm = self._cvm(ttq, cpr)
        if cvm is None:
            db[0x9F34] = bytes.fromhex("3F0001")
            return common.outcome(s, Status.DECLINED, CVM.NO_CVM, DATA_RECORD_TAGS)
        db[0x9F34] = CVM_RESULTS[cvm]

        if s.txn.amount > cfg.floor_limit:
            s.set_tvr(TVR_FLOOR_LIMIT)
        online_capable = s.env.terminal.online_capable and not bit(ttq, 1, 4)
        ac_type = terminal_action_analysis(s, cfg.tac_denial, cfg.tac_online, cfg.tac_default, online_capable)
        if cvm == CVM.ONLINE_PIN and ac_type == apdu.TC:
            ac_type = apdu.ARQC if online_capable else apdu.AAC  # online PIN cannot be approved offline

        cid = common.generate_ac_with_cda(s, ac_type, cda)
        if cid is None:
            return common.outcome(s, Status.DECLINED, cvm, DATA_RECORD_TAGS, L2Error.CAM_FAILED)
        return common.outcome(s, common.status_for(cid), cvm, DATA_RECORD_TAGS)

    @staticmethod
    def _cvm(ttq: bytes, cpr: bytes | None) -> CVM | None:
        """CVM from the TTQ and the CPR. None = no CVM can be performed (decline)."""
        if not bit(ttq, 2, 7):  # CVM not required
            return CVM.NO_CVM
        if cpr:
            if bit(cpr, 1, 8) and bit(ttq, 1, 3):
                return CVM.ONLINE_PIN
            if bit(cpr, 2, 8):
                return CVM.CONFIRMATION_CODE_VERIFIED
            if bit(cpr, 1, 7) and bit(ttq, 1, 2):
                return CVM.SIGNATURE
            return None
        if bit(ttq, 1, 2):
            return CVM.SIGNATURE
        if bit(ttq, 1, 3):
            return CVM.ONLINE_PIN
        return None
