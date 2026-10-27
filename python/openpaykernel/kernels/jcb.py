"""Kernel 5: JCB J/Speedy (EMV Contactless Book C-5), EMV mode.

Flow: Terminal Interchange Profile (9F53) in the PDOL → GET PROCESSING OPTIONS → READ RECORD →
CDA selection → processing restrictions → CVM (on-device CVM, or CVM List with the TIP's CVM
capabilities) → floor limit → terminal action analysis → GENERATE AC (CDA) → outcome.

Terminal Interchange Profile, byte 1 (computed per transaction):
  (1,8) CVM required (set when the amount reaches the CVM required limit)
  (1,7) signature supported      (1,6) online PIN supported
  (1,5) on-device CVM supported  (1,2) EMV contact chip supported
Bytes 2-3 are passed through from configuration (AidConfig.extra[0x9F53]).

Not implemented: legacy (mag-stripe) mode, Combination Options other than EMV mode, Issuer
Update Processing, torn-transaction handling. These bit assignments follow the public
structure of Book C-5 but have NOT been verified against the official specification text.
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
                    0x9F1A, 0x9F33, 0x9F34, 0x9F35, 0x9F53, 0x5A, 0x5F34, 0x57, 0x5F24, 0x84, 0x9F06]

DEFAULT_TIP = bytes.fromhex("720000")


def terminal_interchange_profile(ctx: KernelContext) -> bytes:
    """9F53 for this transaction: configuration value plus the CVM-required bit."""
    tip = bytearray(ctx.aid_cfg.extra.get(0x9F53, DEFAULT_TIP)[:3].ljust(3, b"\x00"))
    tip[0] &= 0x7F
    if ctx.pre.cvm_required_limit_exceeded:
        tip[0] |= 0x80
    return bytes(tip)


class JcbKernel:
    kernel_id = 5

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
        tip = terminal_interchange_profile(ctx)
        db[0x9F53] = tip

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
            # legacy (mag-stripe) mode is not implemented
            return end_application(L2Error.MAGSTRIPE_NOT_SUPPORTED, msg=Message.INSERT_SWIPE_OR_TRY_ANOTHER)

        read_application_data(s)
        check_mandatory(s, [0x5F24, 0x5A, 0x8C])
        cda = common.select_cda(s, aip, bit(s.env.terminal.capabilities, 3, 4))
        processing_restrictions(s)

        cvm_required = bit(tip, 1, 8)
        if cvm_required and bit(aip, 1, 2) and bit(tip, 1, 5):
            db[0x9F34] = bytes.fromhex("010002")
            cvm = CVM.CONFIRMATION_CODE_VERIFIED
        else:
            caps = bytearray(s.env.terminal.capabilities)
            # below the CVM limit only "No CVM required" is offered; above it, what the TIP allows
            caps[1] = ((0x40 if bit(tip, 1, 6) else 0) | (0x20 if bit(tip, 1, 7) else 0)) if cvm_required else 0x08
            res = cvm_list_processing(s, bytes(caps), lambda m: RESULT_UNKNOWN)
            db[0x9F34] = res.results
            cvm = CVM.ONLINE_PIN if res.online_pin else CVM.SIGNATURE if res.signature else CVM.NO_CVM

        if s.txn.amount > cfg.floor_limit:
            s.set_tvr(TVR_FLOOR_LIMIT)
        online_capable = s.env.terminal.online_capable
        ac_type = terminal_action_analysis(s, cfg.tac_denial, cfg.tac_online, cfg.tac_default, online_capable)
        if cvm == CVM.ONLINE_PIN and ac_type == apdu.TC:
            ac_type = apdu.ARQC if online_capable else apdu.AAC  # online PIN cannot be approved offline

        cid = common.generate_ac_with_cda(s, ac_type, cda)
        if cid is None:
            return common.outcome(s, Status.DECLINED, cvm, DATA_RECORD_TAGS, L2Error.CAM_FAILED)
        return common.outcome(s, common.status_for(cid), cvm, DATA_RECORD_TAGS)
