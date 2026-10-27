"""Kernel 4: American Express ExpressPay (EMV Contactless Book C-4), EMV mode.

Flow: Enhanced Contactless Reader Capabilities (9F6E) in the PDOL → GET PROCESSING OPTIONS →
READ RECORD → CDA selection → processing restrictions → CVM (mobile CVM, or CVM List with
the reader's CVM capabilities) → floor limit → terminal action analysis → GENERATE AC (CDA).

9F6E layout used here (byte, bit):
  byte 1: (1,8) contact supported, (1,7) mag-stripe mode supported, (1,5) EMV partial online
          supported, (1,4) mobile supported
  byte 2: (2,8) mobile CVM supported, (2,7) online PIN supported, (2,6) signature supported
  byte 3: (3,8) reader is offline only, (3,7) CVM required (set per transaction)
  byte 4: kernel version / terminal type flags (passed through from configuration)
Mobile CVM Results (9F71, 3 bytes, from the card): byte 3 = 02 means the CVM succeeded.

The reader capabilities are kept in a local variable: tag 9F6E is card data for other
kernels (Visa's Form Factor Indicator), so the value in the shared database is not trusted.

Not implemented: ExpressPay mag-stripe mode, delayed authorisation, the mobile "try again"
flow, DDA. These bit assignments follow the public structure of Book C-4 but have NOT been
verified against the official specification text.
"""
from __future__ import annotations

from .. import apdu, tlv
from ..config import bit
from ..emvproc import (TVR_FLOOR_LIMIT, CardError, Session, check_mandatory, cvm_list_processing, parse_gpo_response,
                       processing_restrictions, read_application_data, terminal_action_analysis, RESULT_UNKNOWN)
from ..entry_point import KernelContext
from ..outcome import CVM, L2Error, Message, Outcome, Status, end_application, select_next, try_another_interface
from . import common

DATA_RECORD_TAGS = [0x9F02, 0x9F03, 0x9F26, 0x9F27, 0x9F36, 0x9F10, 0x9F37, 0x95, 0x9A, 0x9C, 0x5F2A, 0x82,
                    0x9F1A, 0x9F33, 0x9F34, 0x9F35, 0x9F6E, 0x9F71, 0x5A, 0x5F34, 0x57, 0x5F24, 0x84, 0x9F06]

DEFAULT_READER_CAPABILITIES = bytes.fromhex("D8E00003")


def reader_capabilities(ctx: KernelContext) -> bytes:
    """9F6E for this transaction: configuration value plus the per-transaction bits."""
    ecrc = bytearray(ctx.aid_cfg.extra.get(0x9F6E, DEFAULT_READER_CAPABILITIES)[:4].ljust(4, b"\x00"))
    ecrc[2] &= 0x3F
    if ctx.env.terminal.offline_only:
        ecrc[2] |= 0x80
    if ctx.pre.cvm_required_limit_exceeded:
        ecrc[2] |= 0x40
    return bytes(ecrc)


class AmexKernel:
    kernel_id = 4

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
        ecrc = reader_capabilities(ctx)
        db[0x9F6E] = ecrc

        # GET PROCESSING OPTIONS
        s.pdol_data = s.build_dol(db.get(0x9F38, b""))
        r = s.chan.exchange(apdu.get_processing_options(s.pdol_data))
        if r.sw == 0x6984:
            return try_another_interface()
        if not r.ok:
            return select_next(L2Error.STATUS_BYTES, r.sw)
        parse_gpo_response(r.data, db)
        aip = db[0x82]
        if not bit(aip, 2, 8) or not db.get(0x94):
            return end_application(L2Error.MAGSTRIPE_NOT_SUPPORTED, msg=Message.INSERT_SWIPE_OR_TRY_ANOTHER)

        read_application_data(s)
        check_mandatory(s, [0x5F24, 0x5A, 0x8C, 0x8D])
        cda = common.select_cda(s, aip, bit(s.env.terminal.capabilities, 3, 4))
        processing_restrictions(s)

        cvm_required = bit(ecrc, 3, 7)
        mobile = db.get(0x9F71)
        if mobile and len(mobile) == 3 and bit(ecrc, 2, 8) and mobile[2] == 0x02:
            db[0x9F34] = mobile
            cvm = CVM.CONFIRMATION_CODE_VERIFIED
        else:
            caps = bytearray(s.env.terminal.capabilities)
            # Below the CVM limit only "No CVM required" is offered; above it, what the reader supports
            caps[1] = ((0x40 if bit(ecrc, 2, 7) else 0) | (0x20 if bit(ecrc, 2, 6) else 0)) if cvm_required else 0x08
            res = cvm_list_processing(s, bytes(caps), lambda m: RESULT_UNKNOWN)
            db[0x9F34] = res.results
            cvm = CVM.ONLINE_PIN if res.online_pin else CVM.SIGNATURE if res.signature else CVM.NO_CVM

        if s.txn.amount > cfg.floor_limit:
            s.set_tvr(TVR_FLOOR_LIMIT)
        online_capable = s.env.terminal.online_capable and not bit(ecrc, 3, 8)
        ac_type = terminal_action_analysis(s, cfg.tac_denial, cfg.tac_online, cfg.tac_default, online_capable)
        if cvm == CVM.ONLINE_PIN and ac_type == apdu.TC:
            ac_type = apdu.ARQC if online_capable else apdu.AAC  # online PIN cannot be approved offline

        cid = common.generate_ac_with_cda(s, ac_type, cda)
        if cid is None:
            return common.outcome(s, Status.DECLINED, cvm, DATA_RECORD_TAGS, L2Error.CAM_FAILED)
        return common.outcome(s, common.status_for(cid), cvm, DATA_RECORD_TAGS)
