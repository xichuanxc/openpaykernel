"""Kernel 2: Mastercard (EMV Contactless Book C-2), EMV mode.

Implemented: GPO, READ RECORD, processing restrictions, on-device CVM and CVM List
selection, reader limits, floor limit, terminal action analysis, GENERATE AC with CDA,
and outcome plus data record.
Not implemented yet: mag-stripe mode, the Data Exchange (DEK/DET) signals, the torn
transaction log, relay resistance, and IDS / data storage.
"""
from __future__ import annotations

from .. import apdu, tlv
from ..config import bcd_to_int, bit
from ..emvproc import (CardError, Session, check_mandatory, cvm_list_processing, parse_gpo_response,
                       processing_restrictions, read_application_data, terminal_action_analysis, RESULT_UNKNOWN)
from ..entry_point import KernelContext
from ..outcome import CVM, L2Error, Message, Outcome, Status, end_application, select_next
from . import common

DATA_RECORD_TAGS = [0x9F02, 0x9F03, 0x9F26, 0x5F24, 0x82, 0x50, 0x5A, 0x5F34, 0x9F12, 0x9F36, 0x9F07, 0x9F09,
                    0x84, 0x9F27, 0x9F34, 0x9F1E, 0x9F10, 0x9F33, 0x9F1A, 0x9F35, 0x95, 0x57, 0x9F53, 0x5F2A,
                    0x9A, 0x9C, 0x9F37, 0x9F6E, 0x9F7C, 0x9F06]

# Kernel Configuration (DF811B) bits, byte 1
KC_MAGSTRIPE_NOT_SUPPORTED = 8
KC_EMV_MODE_NOT_SUPPORTED = 7
KC_ON_DEVICE_CVM_SUPPORTED = 6


class MastercardKernel:
    kernel_id = 2

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
        kc = db.get(0xDF811B, b"\x20")

        # 1. Initiate application processing
        s.pdol_data = s.build_dol(db.get(0x9F38, b""))
        r = s.chan.exchange(apdu.get_processing_options(s.pdol_data))
        if not r.ok:
            return select_next(L2Error.STATUS_BYTES, r.sw)
        parse_gpo_response(r.data, db)
        aip = db[0x82]
        if not (bit(aip, 2, 8) and not bit(kc, 1, KC_EMV_MODE_NOT_SUPPORTED)):
            return end_application(L2Error.MAGSTRIPE_NOT_SUPPORTED, msg=Message.INSERT_SWIPE_OR_TRY_ANOTHER)

        # 2. Read application data
        if not db.get(0x94):
            raise CardError("AFL missing")
        read_application_data(s)
        check_mandatory(s, [0x5F24, 0x5A, 0x8C, 0x8D])

        # 3. Offline data authentication selection: C-2 supports only CDA
        cda = common.select_cda(s, aip, bit(db.get(0xDF811F, b"\x08"), 1, 4))

        # 4. Processing restrictions
        processing_restrictions(s)

        # 5. Cardholder verification
        amount = s.txn.amount
        cvm_limit = cfg.cvm_required_limit if cfg.cvm_required_limit is not None else \
            bcd_to_int(db.get(0xDF8126, b"\x00"))
        on_device = bit(aip, 1, 2) and bit(kc, 1, KC_ON_DEVICE_CVM_SUPPORTED)
        if on_device and amount > cvm_limit:
            db[0x9F34] = bytes.fromhex("010002")
            cvm = CVM.CONFIRMATION_CODE_VERIFIED
        else:
            caps = bytearray(db.get(0x9F33, bytes(3)))
            caps[1] = db.get(0xDF8118 if amount > cvm_limit else 0xDF8119, b"\x08")[0]
            db[0x9F33] = bytes(caps)
            res = cvm_list_processing(s, bytes(caps), lambda m: RESULT_UNKNOWN)
            db[0x9F34] = res.results
            cvm = CVM.ONLINE_PIN if res.online_pin else CVM.SIGNATURE if res.signature else CVM.NO_CVM

        # 6. Reader limits and terminal risk management
        limit = cfg.cl_transaction_limit_cdcvm if on_device else cfg.cl_transaction_limit
        if limit is None:
            tag = 0xDF8125 if on_device else 0xDF8124
            limit = bcd_to_int(db[tag]) if tag in db else None
        if limit is not None and amount > limit:
            return select_next(L2Error.MAX_LIMIT_EXCEEDED)
        floor = bcd_to_int(db[0xDF8123]) if 0xDF8123 in db else cfg.floor_limit
        if amount > floor:
            s.set_tvr((4, 8))

        # 7. Terminal action analysis
        tac_default = db.get(0xDF8120, cfg.tac_default)
        tac_denial = db.get(0xDF8121, cfg.tac_denial)
        tac_online = db.get(0xDF8122, cfg.tac_online)
        ac_type = terminal_action_analysis(s, tac_denial, tac_online, tac_default,
                                           s.env.terminal.online_capable)

        # 8. GENERATE AC (with CDA when selected)
        cid = common.generate_ac_with_cda(s, ac_type, cda)
        if cid is None:
            return self._outcome(s, Status.DECLINED, cvm, L2Error.CAM_FAILED)
        return self._outcome(s, common.status_for(cid), cvm)

    def _outcome(self, s: Session, status: Status, cvm: CVM, l2: L2Error = L2Error.OK) -> Outcome:
        return common.outcome(s, status, cvm, DATA_RECORD_TAGS, l2)
