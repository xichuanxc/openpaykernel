"""Kernel 2: Mastercard (EMV Contactless Book C-2), EMV mode.

Implemented: GPO, READ RECORD, processing restrictions, on-device CVM and CVM List
selection, reader limits, floor limit, terminal action analysis, GENERATE AC with CDA,
and outcome plus data record.
Not implemented yet: mag-stripe mode, the Data Exchange (DEK/DET) signals, the torn
transaction log, relay resistance, and IDS / data storage.
"""
from __future__ import annotations

from .. import apdu, oda, tlv
from ..config import bcd_to_int, bit
from ..emvproc import (TVR_CDA_FAILED, TVR_ODA_NOT_PERFORMED, CardError, Session, check_mandatory,
                       cvm_list_processing, parse_generate_ac, parse_gpo_response, processing_restrictions,
                       read_application_data, retrieve_icc_pk, terminal_action_analysis, RESULT_UNKNOWN)
from ..entry_point import KernelContext
from ..outcome import (CVM, ErrorIndication, L2Error, Message, Outcome, Status, UIRequest, end_application,
                       select_next)

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
        except CardError as e:
            return end_application(L2Error.CARD_DATA_ERROR, e.sw, Message.PROCESSING_ERROR)
        except tlv.TLVError:
            return end_application(L2Error.PARSING_ERROR, msg=Message.PROCESSING_ERROR)

    def _run(self, ctx: KernelContext, s: Session) -> Outcome:
        db, cfg = s.db, ctx.aid_cfg
        fci = tlv.parse(ctx.fci)
        if not fci or fci[0].tag != 0x6F:
            return select_next(L2Error.PARSING_ERROR)
        db.store_card_data(fci)
        db[0x9F06] = ctx.candidate.adf_name
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
        cda = bit(aip, 1, 1) and bit(db.get(0xDF811F, b"\x08"), 1, 4)
        if not cda:
            s.set_tvr(TVR_ODA_NOT_PERFORMED)
        else:
            rid = db[0x9F06][:5]
            if not db.get(0x8F) or s.env.capks.find(rid, db[0x8F][0], s.txn.date) is None:
                s.set_tvr(TVR_CDA_FAILED)

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

        # 8. GENERATE AC
        request_cda = cda and not s.tvr.get(1, 3) and ac_type != apdu.AAC
        s.cdol1_data = s.build_dol(db[0x8C])
        r = s.chan.exchange(apdu.generate_ac(ac_type | (apdu.CDA_REQUESTED if request_cda else 0), s.cdol1_data))
        if not r.ok:
            return end_application(L2Error.STATUS_BYTES, r.sw, Message.PROCESSING_ERROR)
        children = parse_generate_ac(r.data, db)
        cid = db[0x9F27][0] & 0xC0

        if request_cda and cid != apdu.AAC:
            if 0x9F4B not in db:
                s.set_tvr(TVR_CDA_FAILED)
                return self._outcome(s, Status.DECLINED, cvm, L2Error.CAM_FAILED)
            try:
                icc = retrieve_icc_pk(s)
                tlvs = b"".join(c.encode() for c in children if c.tag != 0x9F4B)
                ac, sig = oda.verify_cda(icc, db[0x9F4B], db[0x9F37], db[0x9F27],
                                         s.pdol_data + s.cdol1_data + tlvs)
                db[0x9F26] = ac
                db[0x9F4C] = sig.icc_dynamic_number
            except oda.OdaError:
                s.set_tvr(TVR_CDA_FAILED)
                return self._outcome(s, Status.DECLINED, cvm, L2Error.CAM_FAILED)
        elif 0x9F26 not in db:
            raise CardError("application cryptogram missing")

        status = {apdu.TC: Status.APPROVED, apdu.ARQC: Status.ONLINE_REQUEST}.get(cid, Status.DECLINED)
        return self._outcome(s, status, cvm)

    def _outcome(self, s: Session, status: Status, cvm: CVM, l2: L2Error = L2Error.OK) -> Outcome:
        s.sync()
        msg = {Status.APPROVED: Message.APPROVED_SIGN if cvm == CVM.SIGNATURE else Message.APPROVED,
               Status.DECLINED: Message.NOT_AUTHORISED,
               Status.ONLINE_REQUEST: Message.AUTHORISING}[status]
        out = Outcome(status, cvm=cvm, receipt=cvm == CVM.SIGNATURE,
                      ui_request=UIRequest(msg, "CARD_READ_OK" if status == Status.ONLINE_REQUEST else "NOT_READY"),
                      error=ErrorIndication(l2=l2))
        out.data_record = {t: s.db[t] for t in DATA_RECORD_TAGS if t in s.db}
        return out
