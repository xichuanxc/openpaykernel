"""Kernel 3: Visa qVSDC (EMV Contactless Book C-3).

Implemented: the qVSDC path. GPO carries the TTQ, the card returns its cryptogram in the GPO
response, and the kernel then reads records, runs fDDA, processing restrictions and
CTQ-driven CVM, and builds the outcome.
Not implemented: MSD (retired by Visa) and Issuer Update Processing.
"""
from __future__ import annotations

from .. import apdu, dol, oda, tlv
from ..config import bit
from ..emvproc import CardError, Session, check_mandatory, parse_afl, parse_gpo_response, read_application_data, \
    retrieve_icc_pk, static_data_to_authenticate
from ..entry_point import KernelContext
from ..outcome import (CVM, ErrorIndication, L2Error, Message, Outcome, Start, Status, UIRequest,
                       end_application, select_next, try_another_interface)

DATA_RECORD_TAGS = [0x82, 0x95, 0x9A, 0x9C, 0x5F2A, 0x9F02, 0x9F03, 0x9F10, 0x9F1A, 0x9F26, 0x9F27,
                    0x9F36, 0x9F37, 0x9F66, 0x9F6C, 0x9F6E, 0x9F7C, 0x5F34, 0x57, 0x5A, 0x5F24, 0x9F34,
                    0x9F33, 0x9F35, 0x84, 0x9F06]

AAC, TC, ARQC = 0x00, 0x40, 0x80


def cid_from_iad(iad: bytes | None) -> int:
    """Visa IAD formats 0/1/3: byte 5 bits 6-5 hold the cryptogram type."""
    if not iad or len(iad) < 5:
        return -1
    return {0: AAC, 1: TC, 2: ARQC}.get((iad[4] >> 4) & 0x03, -1)


class VisaKernel:
    kernel_id = 3

    def start(self, ctx: KernelContext) -> Outcome:
        s = Session.new(ctx.env, ctx.aid_cfg, ctx.txn, ctx.chan)
        try:
            return self._run(ctx, s)
        except CardError as e:
            return end_application(L2Error.CARD_DATA_ERROR, e.sw)
        except tlv.TLVError:
            return end_application(L2Error.PARSING_ERROR)

    def _run(self, ctx: KernelContext, s: Session) -> Outcome:
        db = s.db
        fci = tlv.parse(ctx.fci)
        if not fci or fci[0].tag != 0x6F:
            return select_next(L2Error.PARSING_ERROR)
        db.store_card_data(fci)
        db[0x9F06] = ctx.candidate.adf_name
        ttq = ctx.pre.ttq or ctx.aid_cfg.ttq
        db[0x9F66] = ttq

        pdol = db.get(0x9F38)
        if not pdol or 0x9F66 not in dol.dol_tags(pdol):
            # Without TTQ in the PDOL the card only supports MSD, which we do not implement.
            return end_application(L2Error.CARD_DATA_MISSING, msg=Message.INSERT_SWIPE_OR_TRY_ANOTHER)
        s.pdol_data = s.build_dol(pdol)
        r = s.chan.exchange(apdu.get_processing_options(s.pdol_data))
        if r.sw == 0x6984:
            return try_another_interface()
        if r.sw == 0x6985:
            return select_next(L2Error.STATUS_BYTES, r.sw)
        if r.sw == 0x6986:
            return Outcome(Status.TRY_AGAIN, start=Start.B,
                           ui_request=UIRequest(Message.SEE_PHONE, "PROCESSING", hold_time_ms=1300),
                           ui_on_restart=UIRequest(Message.PRESENT_CARD, "READY_TO_READ"),
                           field_off_request_ms=1300)
        if not r.ok:
            return end_application(L2Error.STATUS_BYTES, r.sw)
        if r.data[:1] != b"\x77":
            return end_application(L2Error.CARD_DATA_ERROR)  # format 1 is not valid for qVSDC
        parse_gpo_response(r.data, db)

        if 0x94 in db and db[0x94]:
            parse_afl(db[0x94])
            read_application_data(s)

        cid = (db[0x9F27][0] & 0xC0) if 0x9F27 in db else cid_from_iad(db.get(0x9F10))
        if cid not in (AAC, TC, ARQC):
            return end_application(L2Error.CARD_DATA_ERROR)
        mandatory = [0x82, 0x9F36, 0x9F10]
        if cid != AAC:
            mandatory.append(0x9F26)
        if 0x57 not in db and 0x5A not in db:
            mandatory.append(0x57)
        check_mandatory(s, mandatory)
        if not _track2_matches_pan(db.get(0x57), db.get(0x5A)):
            return end_application(L2Error.CARD_DATA_ERROR)

        online_capable = s.env.terminal.online_capable and not bit(ttq, 1, 4)
        ctq = db.get(0x9F6C)

        def offline_failure() -> Outcome:
            """Book C-3 rules for an offline transaction that fails a check."""
            if bit(ctq, 1, 6) and online_capable:
                return self._outcome(s, Status.ONLINE_REQUEST, cvm_result)
            if bit(ctq, 1, 5) and bit(ttq, 1, 5):
                return try_another_interface()
            return self._outcome(s, Status.DECLINED, cvm_result)

        # Cardholder verification is decided first; it may move the status
        cvm_result = self._cvm(s, ttq, ctq, cid)
        if cvm_result is None:
            return self._outcome(s, Status.DECLINED, CVM.NO_CVM)

        if cid == AAC:
            return self._outcome(s, Status.DECLINED, cvm_result)
        if cid == ARQC:
            return self._outcome(s, Status.ONLINE_REQUEST, cvm_result)

        # TC: offline approval needs processing restrictions and fDDA to pass
        if cvm_result == CVM.ONLINE_PIN:
            return self._outcome(s, Status.ONLINE_REQUEST if online_capable else Status.DECLINED, cvm_result)
        if 0x5F24 in db and _yymmdd(db[0x5F24].hex()) < _yymmdd(s.txn.date):
            return offline_failure()
        pan = db.get(0x5A) or _pan_from_track2(db.get(0x57))
        if pan and pan.hex().upper().rstrip("F").encode() in s.env.terminal.exception_file:
            return offline_failure()
        if not bit(db[0x82], 1, 6):
            return offline_failure()
        try:
            self._fdda(s)
        except oda.OdaError as e:
            s.db[0xDF8115] = str(e).encode()
            return offline_failure()
        return self._outcome(s, Status.APPROVED, cvm_result)

    # --- fDDA (Book C-3 Annex) ---------------------------------------------------------
    def _fdda(self, s: Session) -> None:
        db = s.db
        if 0x9F4B not in db:
            raise oda.OdaError("SDAD missing")
        icc = retrieve_icc_pk(s)
        card_auth = db.get(0x9F69)
        if card_auth and card_auth[0] == 0x01:
            tdd = db[0x9F37] + db[0x9F02] + db[0x5F2A] + card_auth
        else:
            tdd = db[0x9F37]
        static_data_to_authenticate(s)  # validates records once more
        sig = oda.verify_dynamic_signature(icc, db[0x9F4B], tdd)
        db[0x9F4C] = sig.icc_dynamic_number

    # --- CVM (Book C-3 section 5.6) ------------------------------------------------------
    def _cvm(self, s: Session, ttq: bytes, ctq: bytes | None, cid: int) -> CVM | None:
        if not bit(ttq, 2, 7):  # CVM not required
            return CVM.NO_CVM
        if ctq:
            if bit(ctq, 1, 8) and bit(ttq, 1, 3):
                return CVM.ONLINE_PIN
            if bit(ctq, 2, 8):  # consumer device CVM performed
                cad = s.db.get(0x9F69)
                if cad and len(cad) >= 7 and cad[5:7] != ctq[:2]:
                    return None
                return CVM.CONFIRMATION_CODE_VERIFIED
            if bit(ctq, 1, 7) and bit(ttq, 1, 2):
                return CVM.SIGNATURE
            return None
        if bit(ttq, 1, 2):
            return CVM.SIGNATURE
        if bit(ttq, 1, 3) and cid == ARQC:
            return CVM.ONLINE_PIN
        return None

    def _outcome(self, s: Session, status: Status, cvm: CVM) -> Outcome:
        s.sync()
        msg = {Status.APPROVED: Message.APPROVED_SIGN if cvm == CVM.SIGNATURE else Message.APPROVED,
               Status.DECLINED: Message.NOT_AUTHORISED,
               Status.ONLINE_REQUEST: Message.AUTHORISING}[status]
        out = Outcome(status, cvm=cvm, receipt=cvm == CVM.SIGNATURE,
                      ui_request=UIRequest(msg, "CARD_READ_OK" if status == Status.ONLINE_REQUEST else "NOT_READY"),
                      online_response_data=None,
                      error=ErrorIndication())
        out.data_record = {t: s.db[t] for t in DATA_RECORD_TAGS if t in s.db}
        return out


def _yymmdd(d: str) -> int:
    if len(d) != 6 or not d.isdigit():
        raise CardError(f"invalid date {d}")
    yy = int(d[:2])
    return (2000 + yy if yy < 50 else 1900 + yy) * 10000 + int(d[2:6])


def _pan_from_track2(t2: bytes | None) -> bytes | None:
    if not t2:
        return None
    h = t2.hex().upper()
    p = h.split("D")[0]
    return bytes.fromhex(p + ("F" if len(p) % 2 else ""))


def _track2_matches_pan(t2: bytes | None, pan: bytes | None) -> bool:
    if not t2 or not pan:
        return True
    return t2.hex().upper().split("D")[0] == pan.hex().upper().rstrip("F")
