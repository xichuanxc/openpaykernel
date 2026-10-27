"""Contact EMV kernel (EMV Books 1-4).

The flow follows Book 3 section 10: application selection, initiate application processing,
read application data, offline data authentication, processing restrictions, cardholder
verification, terminal risk management, terminal action analysis, card action analysis,
online processing, issuer script processing and completion.

The host answers through ContactHost callbacks: application choice, PIN entry and the online
authorisation.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol

from . import apdu, dol, oda, tlv
from .config import AidConfig, Environment, Transaction, bit
from .emvproc import (RESULT_FAILED, RESULT_SUCCESS, TSI_CARD_RISK, TSI_CVM, TSI_ISSUER_AUTH, TSI_ODA,
                      TSI_SCRIPT, TVR_CDA_FAILED, TVR_DDA_FAILED, TVR_DEFAULT_TDOL,
                      TVR_ISSUER_AUTH_FAILED, TVR_ODA_NOT_PERFORMED, TVR_PIN_NOT_ENTERED, TVR_PIN_PAD_MISSING,
                      TVR_PIN_TRY_LIMIT, TVR_SCRIPT_FAILED_AFTER, TVR_SCRIPT_FAILED_BEFORE, TVR_SDA_FAILED,
                      TVR_SDA_SELECTED, CVM_ENC_PIN, CVM_ENC_PIN_SIG, CVM_ONLINE_PIN, CardError, Session,
                      check_mandatory, cvm_list_processing, default_action, parse_generate_ac,
                      parse_gpo_response, processing_restrictions, read_application_data, retrieve_icc_pk,
                      retrieve_issuer_pk, static_data_to_authenticate, terminal_action_analysis,
                      terminal_risk_management)
from .outcome import CVM, ErrorIndication, L2Error, Message, Outcome, Status, UIRequest

PSE = b"1PAY.SYS.DDF01"


@dataclass
class AppCandidate:
    aid: bytes
    label: str
    priority: int
    needs_confirmation: bool
    cfg: AidConfig


@dataclass
class OnlineResponse:
    approved: bool
    arc: bytes = b"00"                     # 8A, two ASCII characters
    issuer_auth_data: bytes | None = None  # 91
    scripts: bytes = b""                   # concatenated 71/72 templates


class ContactHost(Protocol):
    def choose_application(self, candidates: list[AppCandidate]) -> int | None: ...

    def enter_pin(self, online: bool, tries_left: int | None) -> str | None: ...

    def go_online(self, data: dict[int, bytes]) -> OnlineResponse | None: ...


class AutoHost:
    """A host that picks the first application, returns a fixed PIN, and answers online with a canned result."""

    def __init__(self, pin: str | None = "1234", online: OnlineResponse | None = None) -> None:
        self.pin = pin
        self.online = online if online is not None else OnlineResponse(True)
        self.online_requests: list[dict[int, bytes]] = []
        self.pin_requests: list[tuple[bool, int | None]] = []

    def choose_application(self, candidates):
        return 0

    def enter_pin(self, online, tries_left):
        self.pin_requests.append((online, tries_left))
        return self.pin

    def go_online(self, data):
        self.online_requests.append(data)
        return self.online


ONLINE_TAGS = [0x9F26, 0x9F27, 0x9F10, 0x9F37, 0x9F36, 0x95, 0x9A, 0x9C, 0x9F02, 0x5F2A, 0x82, 0x9F1A,
               0x9F03, 0x9F33, 0x9F34, 0x9F35, 0x9F1E, 0x84, 0x9F09, 0x9F41, 0x5A, 0x5F34, 0x57, 0x5F24, 0x9F06]


@dataclass
class ContactResult:
    outcome: Outcome
    script_results: bytes = b""
    data: dict[int, bytes] = field(default_factory=dict)


class ContactKernel:
    def __init__(self, env: Environment, host: ContactHost) -> None:
        self.env = env
        self.host = host

    # ------------------------------------------------------------------ public entry
    def process(self, reader: apdu.Reader, txn: Transaction, log: list | None = None) -> ContactResult:
        chan = apdu.Channel(reader, log)
        try:
            cands = self.build_candidate_list(chan)
        except CardError as e:
            return self._end(L2Error.CARD_DATA_ERROR, e.sw)
        while cands:
            cand = self._choose(cands)
            if cand is None:
                return self._end(L2Error.EMPTY_CANDIDATE_LIST)
            r = chan.exchange(apdu.select(cand.aid))
            if not r.ok:
                cands.remove(cand)
                continue
            s = Session.new(self.env, cand.cfg, txn, chan)
            try:
                res = self._process_app(s, r.data)
            except CardError as e:
                return self._end(L2Error.CARD_DATA_ERROR, e.sw, s)
            except tlv.TLVError:
                return self._end(L2Error.PARSING_ERROR, 0, s)
            if res is None:  # GPO "conditions of use not satisfied": try another application
                cands.remove(cand)
                continue
            return res
        return self._end(L2Error.EMPTY_CANDIDATE_LIST)

    # ------------------------------------------------------------------ selection (Book 1 12)
    def build_candidate_list(self, chan: apdu.Channel) -> list[AppCandidate]:
        cands = self._pse(chan)
        if not cands:
            cands = self._list_of_aids(chan)
        cands.sort(key=lambda c: (c.priority == 0, c.priority))
        return cands

    def _match(self, aid: bytes) -> AidConfig | None:
        for c in self.env.aids:
            if aid == c.aid or (c.partial_match and aid.startswith(c.aid)):
                return c
        return None

    def _pse(self, chan: apdu.Channel) -> list[AppCandidate]:
        r = chan.exchange(apdu.select(PSE))
        if r.sw == 0x6A81:
            raise CardError("card blocked", r.sw)
        if not r.ok:
            return []
        try:
            sfi_t = tlv.find(r.data, 0x88)
        except tlv.TLVError:
            return []
        if sfi_t is None or len(sfi_t.value) != 1 or not 1 <= sfi_t.value[0] <= 30:
            return []
        sfi = sfi_t.value[0]
        cands = []
        for rec in range(1, 256):
            rr = chan.exchange(apdu.read_record(sfi, rec))
            if rr.sw == 0x6A83:
                break
            if not rr.ok:
                return []
            try:
                nodes = tlv.parse(rr.data)
            except tlv.TLVError:
                return []
            if not nodes or nodes[0].tag != 0x70:
                return []
            for e in nodes[0].children:
                if e.tag != 0x61:
                    continue
                aid = e.find(0x4F)
                if aid is None:
                    continue
                cfg = self._match(aid.value)
                if cfg:
                    cands.append(self._candidate(aid.value, e, cfg))
        return cands

    def _list_of_aids(self, chan: apdu.Channel) -> list[AppCandidate]:
        cands: list[AppCandidate] = []
        for cfg in self.env.aids:
            first = True
            while True:
                r = chan.exchange(apdu.select(cfg.aid, first))
                if r.sw == 0x6A81 and first:
                    raise CardError("card blocked", r.sw)
                if r.sw not in (0x9000, 0x6283):
                    break
                try:
                    fci = tlv.parse(r.data)
                    df = fci[0].find(0x84) if fci else None
                except tlv.TLVError:
                    df = None
                if df is None:
                    break
                if r.sw == 0x9000:
                    if df.value == cfg.aid:
                        cands.append(self._candidate(df.value, fci[0], cfg))
                        break
                    if cfg.partial_match and df.value.startswith(cfg.aid):
                        cands.append(self._candidate(df.value, fci[0], cfg))
                if not cfg.partial_match:
                    break
                first = False
        return cands

    @staticmethod
    def _candidate(aid: bytes, node: tlv.TLV, cfg: AidConfig) -> AppCandidate:
        label = node.find(0x50)
        prio = node.find(0x87)
        p = prio.value[0] if prio and prio.value else 0
        return AppCandidate(aid, label.value.decode("ascii", "replace") if label else aid.hex().upper(),
                            p & 0x0F, bool(p & 0x80), cfg)

    def _choose(self, cands: list[AppCandidate]) -> AppCandidate | None:
        if len(cands) == 1 and not cands[0].needs_confirmation:
            return cands[0]
        idx = self.host.choose_application(cands)
        if idx is None or not 0 <= idx < len(cands):
            return None
        return cands[idx]

    # ------------------------------------------------------------------ per application
    def _process_app(self, s: Session, fci_raw: bytes) -> ContactResult | None:
        db = s.db
        fci = tlv.parse(fci_raw)
        if not fci or fci[0].tag != 0x6F or fci[0].find(0x84) is None:
            raise CardError("FCI invalid")
        db.store_card_data(fci)
        db[0x4F] = db[0x84]
        db[0x9F06] = s.aid_cfg.aid

        # Initiate application processing (Book 3 10.1)
        s.pdol_data = s.build_dol(db.get(0x9F38, b""))
        r = s.chan.exchange(apdu.get_processing_options(s.pdol_data))
        if r.sw == 0x6985:
            return None
        if not r.ok:
            raise CardError("GPO failed", r.sw)
        parse_gpo_response(r.data, db)

        # Read application data (Book 3 10.2)
        read_application_data(s)
        check_mandatory(s, [0x5F24, 0x5A, 0x8C, 0x8D])
        aip = db[0x82]
        caps = s.env.terminal.capabilities

        # Offline data authentication (Book 3 10.3)
        cda = self._oda(s, aip, caps)

        processing_restrictions(s)

        # Cardholder verification (Book 3 10.5)
        cvm_res = cvm_list_processing(s, caps, lambda m: self._perform_pin(s, m))
        db[0x9F34] = cvm_res.results
        if bit(aip, 1, 5):
            s.set_tsi(TSI_CVM)
        cvm = (CVM.ONLINE_PIN if cvm_res.online_pin else CVM.SIGNATURE if cvm_res.signature
               else CVM.OFFLINE_PIN if cvm_res.offline_pin else CVM.NO_CVM)

        # Terminal risk management (Book 3 10.6), mandatory when the AIP asks for it or above the floor limit
        if bit(aip, 1, 4) or s.txn.amount >= s.aid_cfg.floor_limit:
            terminal_risk_management(s)

        # Terminal action analysis (Book 3 10.7)
        cfg = s.aid_cfg
        online_capable = s.env.terminal.online_capable
        ac = terminal_action_analysis(s, cfg.tac_denial, cfg.tac_online, cfg.tac_default, online_capable)

        # Card action analysis (Book 3 10.8): first GENERATE AC
        cid = self._generate_ac(s, ac, db[0x8C], cda, first=True)
        s.set_tsi(TSI_CARD_RISK)
        if cid is None:
            return self._finish(s, Status.DECLINED, cvm)
        if cid == apdu.TC:
            db[0x8A] = b"Y1"
            return self._finish(s, Status.APPROVED, cvm)
        if cid == apdu.AAC:
            db[0x8A] = b"Z1"
            return self._finish(s, Status.DECLINED, cvm)

        # Online processing (Book 3 10.9)
        s.sync()
        rsp = self.host.go_online({t: db[t] for t in ONLINE_TAGS if t in db})
        script_results = bytearray()
        if rsp is None:
            final = default_action(s, cfg.tac_default)
            db[0x8A] = b"Y3" if final == apdu.TC else b"Z3"
        else:
            db[0x8A] = rsp.arc
            if rsp.issuer_auth_data is not None:
                db[0x91] = rsp.issuer_auth_data
                cdol2_has_91 = 0x91 in dol.dol_tags(db[0x8D])
                if bit(aip, 1, 3) and not cdol2_has_91:
                    er = s.chan.exchange(apdu.external_authenticate(rsp.issuer_auth_data))
                    s.set_tsi(TSI_ISSUER_AUTH)
                    if not er.ok:
                        s.set_tvr(TVR_ISSUER_AUTH_FAILED)
                elif cdol2_has_91:
                    s.set_tsi(TSI_ISSUER_AUTH)
            script_results += self._run_scripts(s, rsp.scripts, 0x71)
            final = apdu.TC if rsp.approved else apdu.AAC

        # Completion (Book 3 10.11): second GENERATE AC
        cid2 = self._generate_ac(s, final, db[0x8D], cda, first=False)
        if rsp is not None:
            script_results += self._run_scripts(s, rsp.scripts, 0x72)
        if script_results:
            db[0x9F5B] = bytes(script_results)
        status = Status.APPROVED if cid2 == apdu.TC else Status.DECLINED
        return self._finish(s, status, cvm, bytes(script_results))

    # ------------------------------------------------------------------ ODA
    def _oda(self, s: Session, aip: bytes, caps: bytes) -> bool:
        """Run SDA/DDA now. Return True when CDA is to be done with GENERATE AC."""
        if bit(aip, 1, 1) and bit(caps, 3, 4):
            s.set_tsi(TSI_ODA)
            try:
                retrieve_icc_pk(s)
                return True
            except oda.OdaError:
                s.set_tvr(TVR_CDA_FAILED)
                return False
        if bit(aip, 1, 6) and bit(caps, 3, 7):
            s.set_tsi(TSI_ODA)
            try:
                icc = retrieve_icc_pk(s)
                ddol = s.db.get(0x9F49) or s.aid_cfg.default_ddol
                if 0x9F37 not in dol.dol_tags(ddol):
                    raise oda.OdaError("DDOL without unpredictable number")
                ddol_data = s.build_dol(ddol)
                r = s.chan.exchange(apdu.internal_authenticate(ddol_data))
                if not r.ok:
                    raise oda.OdaError("INTERNAL AUTHENTICATE failed")
                n = tlv.parse(r.data)[0]
                sdad = n.value if n.tag == 0x80 else (n.find(0x9F4B).value if n.find(0x9F4B) else b"")
                sig = oda.verify_dynamic_signature(icc, sdad, ddol_data)
                s.db[0x9F4B] = sdad
                s.db[0x9F4C] = sig.icc_dynamic_number
            except (oda.OdaError, tlv.TLVError, IndexError):
                s.set_tvr(TVR_DDA_FAILED)
            return False
        if bit(aip, 1, 7) and bit(caps, 3, 8):
            s.set_tsi(TSI_ODA)
            s.set_tvr(TVR_SDA_SELECTED)
            try:
                if 0x93 not in s.db:
                    raise oda.OdaError("SSAD missing")
                issuer = retrieve_issuer_pk(s)
                s.db[0x9F45] = oda.verify_sda(issuer, s.db[0x93], static_data_to_authenticate(s))
            except oda.OdaError:
                s.set_tvr(TVR_SDA_FAILED)
            return False
        s.set_tvr(TVR_ODA_NOT_PERFORMED)
        return False

    # ------------------------------------------------------------------ PIN
    def _perform_pin(self, s: Session, method: int) -> int:
        caps = s.env.terminal.capabilities
        if method == CVM_ONLINE_PIN:
            pin = self.host.enter_pin(True, None)
            if pin is None:
                s.set_tvr(TVR_PIN_NOT_ENTERED)
                return RESULT_FAILED
            return RESULT_SUCCESS
        if not (bit(caps, 2, 8) or bit(caps, 2, 5)):
            s.set_tvr(TVR_PIN_PAD_MISSING)
            return RESULT_FAILED
        tries = None
        r = s.chan.exchange(apdu.get_data(0x9F17))
        if r.ok:
            t = tlv.find(r.data, 0x9F17)
            if t is not None:
                tries = t.value[0]
                if tries == 0:
                    s.set_tvr(TVR_PIN_TRY_LIMIT)
                    return RESULT_FAILED
        enciphered = method in (CVM_ENC_PIN, CVM_ENC_PIN_SIG)
        while True:
            pin = self.host.enter_pin(False, tries)
            if pin is None:
                s.set_tvr(TVR_PIN_NOT_ENTERED)
                return RESULT_FAILED
            block = apdu.plaintext_pin_block(pin)
            if enciphered:
                try:
                    cmd = self._enciphered_verify(s, block)
                except (oda.OdaError, CardError):
                    return RESULT_FAILED
            else:
                cmd = apdu.verify(block)
            r = s.chan.exchange(cmd)
            if r.ok:
                return RESULT_SUCCESS
            if r.sw >> 4 == 0x63C:
                tries = r.sw & 0x0F
                if tries == 0:
                    s.set_tvr(TVR_PIN_TRY_LIMIT)
                    return RESULT_FAILED
                continue
            if r.sw in (0x6983, 0x6984):
                s.set_tvr(TVR_PIN_TRY_LIMIT)
                return RESULT_FAILED
            raise CardError("VERIFY failed", r.sw)

    def _enciphered_verify(self, s: Session, pin_block: bytes) -> bytes:
        db = s.db
        if 0x9F2D in db:
            issuer = retrieve_issuer_pk(s)
            key = oda.recover_icc_pk(issuer, db[0x9F2D], db.get(0x9F2F), db.get(0x9F2E, b"\x03"),
                                     b"", db[0x5A], s.txn.date)
        else:
            key = retrieve_icc_pk(s)
        r = s.chan.exchange(apdu.get_challenge())
        if not r.ok or len(r.data) != 8:
            raise CardError("GET CHALLENGE failed", r.sw)
        pad = s.env.rng(key.size - 17)
        block = b"\x7F" + pin_block + r.data + pad
        n = int.from_bytes(key.modulus, "big")
        e = int.from_bytes(key.exponent, "big")
        enc = pow(int.from_bytes(block, "big"), e, n).to_bytes(key.size, "big")
        return apdu.verify(enc, 0x88)

    # ------------------------------------------------------------------ GENERATE AC
    def _generate_ac(self, s: Session, ac: int, cdol: bytes, cda: bool, first: bool) -> int | None:
        db = s.db
        if 0x98 in dol.dol_tags(cdol):
            tdol = db.get(0x97)
            if tdol is None:
                tdol = s.aid_cfg.default_tdol
                if tdol:
                    s.set_tvr(TVR_DEFAULT_TDOL)
            db[0x98] = hashlib.sha1(s.build_dol(tdol)).digest()
        data = s.build_dol(cdol)
        if first:
            s.cdol1_data = data
        use_cda = cda and ac != apdu.AAC and not s.tvr.get(1, 3)
        r = s.chan.exchange(apdu.generate_ac(ac | (apdu.CDA_REQUESTED if use_cda else 0), data))
        if not r.ok:
            raise CardError("GENERATE AC failed", r.sw)
        for t in (0x9F26, 0x9F4B, 0x9F27):
            db.pop(t, None)
        children = parse_generate_ac(r.data, db)
        cid = db[0x9F27][0] & 0xC0
        if not _cid_allowed(ac, cid):
            raise CardError("card returned a stronger cryptogram than requested")
        if use_cda and cid != apdu.AAC:
            try:
                icc = retrieve_icc_pk(s)
                if 0x9F4B not in db:
                    raise oda.OdaError("SDAD missing")
                tlvs = b"".join(c.encode() for c in children if c.tag != 0x9F4B)
                tc_input = s.pdol_data + s.cdol1_data + (data if not first else b"") + tlvs
                acv, _ = oda.verify_cda(icc, db[0x9F4B], db[0x9F37], db[0x9F27], tc_input)
                db[0x9F26] = acv
            except oda.OdaError:
                s.set_tvr(TVR_CDA_FAILED)
                return None
        elif 0x9F26 not in db:
            raise CardError("cryptogram missing")
        return cid

    # ------------------------------------------------------------------ scripts (Book 3 10.10)
    def _run_scripts(self, s: Session, scripts: bytes, which: int) -> bytes:
        if not scripts:
            return b""
        out = bytearray()
        for tmpl in tlv.parse(scripts):
            if tmpl.tag != which:
                continue
            sid = tmpl.find(0x9F18)
            seq, result = 0, 0x20
            for c in tmpl.children:
                if c.tag != 0x86:
                    continue
                seq += 1
                r = s.chan.exchange(c.value)
                if r.sw >> 8 not in (0x90, 0x62, 0x63):
                    result = 0x10 | min(seq, 0x0F)
                    s.set_tvr(TVR_SCRIPT_FAILED_BEFORE if which == 0x71 else TVR_SCRIPT_FAILED_AFTER)
                    break
            s.set_tsi(TSI_SCRIPT)
            out += bytes([result]) + (sid.value if sid else bytes(4))
        return bytes(out)

    # ------------------------------------------------------------------ results
    def _finish(self, s: Session, status: Status, cvm: CVM, scripts: bytes = b"") -> ContactResult:
        s.sync()
        msg = Message.APPROVED if status == Status.APPROVED else Message.NOT_AUTHORISED
        out = Outcome(status, cvm=cvm, receipt=cvm == CVM.SIGNATURE, ui_request=UIRequest(msg))
        data = dict(s.db.items())
        out.data_record = {t: data[t] for t in ONLINE_TAGS + [0x8A, 0x9B] if t in data}
        return ContactResult(out, scripts, data)

    def _end(self, l2: L2Error, sw: int = 0, s: Session | None = None) -> ContactResult:
        out = Outcome(Status.END_APPLICATION, error=ErrorIndication(l2=l2, sw12=sw),
                      ui_request=UIRequest(Message.PROCESSING_ERROR))
        return ContactResult(out, b"", dict(s.db.items()) if s else {})


def _cid_allowed(requested: int, got: int) -> bool:
    if got == apdu.AAC:
        return True
    if got == apdu.ARQC:
        return requested in (apdu.ARQC, apdu.TC)
    if got == apdu.TC:
        return requested == apdu.TC
    return False
