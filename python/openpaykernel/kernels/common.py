"""Steps shared by the contactless kernels that finish with GENERATE AC (kernels 2, 4, 5, 6)."""
from __future__ import annotations

from .. import apdu, oda, tlv
from ..emvproc import (TVR_CDA_FAILED, TVR_ODA_NOT_PERFORMED, CardError, Session, parse_generate_ac,
                       retrieve_icc_pk)
from ..outcome import CVM, ErrorIndication, L2Error, Message, Outcome, Status, UIRequest


class StatusWordError(CardError):
    """GENERATE AC answered with an error status word: the outcome reports L2 STATUS_BYTES."""


def store_fci(s: Session, fci_raw: bytes, adf_name: bytes) -> bool:
    """Store the FCI of the selected application. False = not an FCI template (select next)."""
    fci = tlv.parse(fci_raw)
    if not fci or fci[0].tag != 0x6F:
        return False
    s.db.store_card_data(fci)
    s.db[0x9F06] = adf_name
    return True


def select_cda(s: Session, aip: bytes, terminal_supports_cda: bool) -> bool:
    """CDA is used when card and terminal support it. A missing CA key marks CDA as failed."""
    if not (aip and aip[0] & 0x01 and terminal_supports_cda):
        s.set_tvr(TVR_ODA_NOT_PERFORMED)
        return False
    rid = s.db[0x9F06][:5]
    if not s.db.get(0x8F) or s.env.capks.find(rid, s.db[0x8F][0], s.txn.date) is None:
        s.set_tvr(TVR_CDA_FAILED)
    return True


def generate_ac_with_cda(s: Session, ac_type: int, cda: bool) -> int | None:
    """Send GENERATE AC with CDOL1 (CDA requested when possible) and verify the response.

    Returns the cryptogram type (apdu.AAC / TC / ARQC), or None when CDA verification failed
    (TVR 'CDA failed' is then set). Raises CardError on a card error.
    """
    db = s.db
    request_cda = cda and not s.tvr.get(1, 3) and ac_type != apdu.AAC
    s.cdol1_data = s.build_dol(db.get(0x8C, b""))
    r = s.chan.exchange(apdu.generate_ac(ac_type | (apdu.CDA_REQUESTED if request_cda else 0), s.cdol1_data))
    if not r.ok:
        raise StatusWordError("GENERATE AC failed", r.sw)
    children = parse_generate_ac(r.data, db)
    cid = db[0x9F27][0] & 0xC0
    if request_cda and cid != apdu.AAC:
        if 0x9F4B not in db:
            s.set_tvr(TVR_CDA_FAILED)
            return None
        try:
            icc = retrieve_icc_pk(s)
            tlvs = b"".join(c.encode() for c in children if c.tag != 0x9F4B)
            ac, sig = oda.verify_cda(icc, db[0x9F4B], db[0x9F37], db[0x9F27], s.pdol_data + s.cdol1_data + tlvs)
            db[0x9F26] = ac
            db[0x9F4C] = sig.icc_dynamic_number
        except oda.OdaError:
            s.set_tvr(TVR_CDA_FAILED)
            return None
    elif 0x9F26 not in db:
        raise CardError("application cryptogram missing")
    return cid


def status_for(cid: int) -> Status:
    return {apdu.TC: Status.APPROVED, apdu.ARQC: Status.ONLINE_REQUEST}.get(cid, Status.DECLINED)


def outcome(s: Session, status: Status, cvm: CVM, record_tags: list[int], l2: L2Error = L2Error.OK) -> Outcome:
    s.sync()
    msg = {Status.APPROVED: Message.APPROVED_SIGN if cvm == CVM.SIGNATURE else Message.APPROVED,
           Status.DECLINED: Message.NOT_AUTHORISED,
           Status.ONLINE_REQUEST: Message.AUTHORISING}[status]
    out = Outcome(status, cvm=cvm, receipt=cvm == CVM.SIGNATURE,
                  ui_request=UIRequest(msg, "CARD_READ_OK" if status == Status.ONLINE_REQUEST else "NOT_READY"),
                  error=ErrorIndication(l2=l2))
    out.data_record = {t: s.db[t] for t in record_tags if t in s.db}
    return out
