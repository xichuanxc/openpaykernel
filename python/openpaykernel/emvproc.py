"""EMV processing steps shared by the contact kernel and the contactless EMV-mode kernels.

References: EMV Book 3 (sections 10.2-10.8) and Book 4 (sections 6.3 and 6.5).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import apdu, dol, oda, tlv
from .config import AidConfig, Bits, Environment, Transaction, bcd_to_int, bit
from .tags import is_terminal_source
from .tlv import TLVDatabase


MAX_COMMAND_DATA = 252  # so that e.g. 83 81 FC <data> still fits a short APDU


class CardError(Exception):
    """A card response violates the specification. The transaction is terminated."""

    def __init__(self, msg: str, sw: int = 0) -> None:
        super().__init__(msg)
        self.sw = sw


# --- TVR / TSI bit positions (Book 3 Annex C5/C6) -------------------------------------
TVR_ODA_NOT_PERFORMED = (1, 8)
TVR_SDA_FAILED = (1, 7)
TVR_ICC_DATA_MISSING = (1, 6)
TVR_EXCEPTION_FILE = (1, 5)
TVR_DDA_FAILED = (1, 4)
TVR_CDA_FAILED = (1, 3)
TVR_SDA_SELECTED = (1, 2)
TVR_APP_VERSION_DIFFERS = (2, 8)
TVR_EXPIRED = (2, 7)
TVR_NOT_EFFECTIVE = (2, 6)
TVR_SERVICE_NOT_ALLOWED = (2, 5)
TVR_NEW_CARD = (2, 4)
TVR_CVM_FAILED = (3, 8)
TVR_UNRECOGNISED_CVM = (3, 7)
TVR_PIN_TRY_LIMIT = (3, 6)
TVR_PIN_PAD_MISSING = (3, 5)
TVR_PIN_NOT_ENTERED = (3, 4)
TVR_ONLINE_PIN = (3, 3)
TVR_FLOOR_LIMIT = (4, 8)
TVR_LCOL_EXCEEDED = (4, 7)
TVR_UCOL_EXCEEDED = (4, 6)
TVR_RANDOM_ONLINE = (4, 5)
TVR_MERCHANT_FORCED_ONLINE = (4, 4)
TVR_DEFAULT_TDOL = (5, 8)
TVR_ISSUER_AUTH_FAILED = (5, 7)
TVR_SCRIPT_FAILED_BEFORE = (5, 6)
TVR_SCRIPT_FAILED_AFTER = (5, 5)

TSI_ODA = (1, 8)
TSI_CVM = (1, 7)
TSI_CARD_RISK = (1, 6)
TSI_ISSUER_AUTH = (1, 5)
TSI_TRM = (1, 4)
TSI_SCRIPT = (1, 3)


@dataclass
class Session:
    """Mutable state of one transaction on one application."""
    env: Environment
    aid_cfg: AidConfig
    txn: Transaction
    chan: apdu.Channel
    db: TLVDatabase
    tvr: Bits
    tsi: Bits
    static_data: bytearray
    pdol_data: bytes = b""
    cdol1_data: bytes = b""

    @classmethod
    def new(cls, env: Environment, aid_cfg: AidConfig, txn: Transaction, chan: apdu.Channel) -> "Session":
        db = TLVDatabase()
        db.update(env.terminal.tags())
        db.update(txn.tags())
        db.update(aid_cfg.extra)
        db[0x9F09] = aid_cfg.app_version
        db[0x9F1B] = aid_cfg.floor_limit.to_bytes(4, "big")
        db[0x9F37] = env.rng(4)
        s = cls(env, aid_cfg, txn, chan, db, Bits(5), Bits(2), bytearray())
        s.sync()
        return s

    def sync(self) -> None:
        self.db[0x95] = bytes(self.tvr)
        self.db[0x9B] = bytes(self.tsi)

    def set_tvr(self, pos: tuple[int, int]) -> None:
        self.tvr.set(*pos)
        self.sync()

    def set_tsi(self, pos: tuple[int, int]) -> None:
        self.tsi.set(*pos)
        self.sync()

    def build_dol(self, d: bytes) -> bytes:
        self.sync()
        try:
            out = dol.build_dol(d, self.db.get)
        except tlv.TLVError as e:
            raise CardError(f"DOL malformed: {e}")
        if len(out) > MAX_COMMAND_DATA:
            raise CardError("DOL requests more data than fits in a command APDU")
        return out


# --- Initiate application processing ---------------------------------------------------

def parse_gpo_response(rsp: bytes, db: TLVDatabase) -> None:
    nodes = tlv.parse(rsp)
    if len(nodes) != 1:
        raise CardError("GPO response is not a single template")
    n = nodes[0]
    if n.tag == 0x80:
        if len(n.value) < 2 or (len(n.value) - 2) % 4:
            raise CardError("GPO format 1 length invalid")
        db[0x82] = n.value[:2]
        db[0x94] = n.value[2:]
    elif n.tag == 0x77:
        db.store_card_data(n.children)
        if 0x82 not in db:
            raise CardError("AIP missing in GPO response")
    else:
        raise CardError(f"unexpected GPO template {n.tag:X}")


def parse_afl(afl: bytes) -> list[tuple[int, int, int, int]]:
    if len(afl) % 4:
        raise CardError("AFL length not a multiple of 4")
    out = []
    for i in range(0, len(afl), 4):
        sfi, first, last, n_oda = afl[i] >> 3, afl[i + 1], afl[i + 2], afl[i + 3]
        if not 1 <= sfi <= 30 or first == 0 or last < first or n_oda > last - first + 1 or afl[i] & 0x07:
            raise CardError("AFL entry invalid")
        out.append((sfi, first, last, n_oda))
    return out


def read_application_data(s: Session, *, allow_duplicates: bool = False) -> None:
    """READ RECORD loop over the AFL (Book 3 10.2). Collects the static data for ODA as it goes."""
    afl = s.db.get(0x94, b"")
    oda_ok = True
    for sfi, first, last, n_oda in parse_afl(afl):
        for rec_no in range(first, last + 1):
            r = s.chan.exchange(apdu.read_record(sfi, rec_no))
            if not r.ok:
                raise CardError(f"READ RECORD {sfi}/{rec_no} failed", r.sw)
            try:
                nodes = tlv.parse(r.data)
            except tlv.TLVError as e:
                raise CardError(f"record parse error: {e}")
            if sfi <= 10 and (len(nodes) != 1 or nodes[0].tag != 0x70):
                raise CardError("record template is not 70")
            for c in tlv.flatten(nodes):
                if _terminal_tag(c.tag):
                    continue  # never let the card overwrite terminal data
                if c.tag in s.db and not allow_duplicates:
                    raise CardError(f"duplicate data object {c.tag:X}")
                s.db[c.tag] = c.value
            if rec_no - first < n_oda:
                if sfi <= 10:
                    s.static_data += nodes[0].value if nodes and nodes[0].tag == 0x70 else b""
                elif r.data[:1] == b"\x70":
                    s.static_data += r.data
                else:
                    oda_ok = False
    if not oda_ok:
        s.db[0xDF00] = b"\x01"  # internal marker: static data invalid → ODA fails


def _terminal_tag(t: int) -> bool:
    return is_terminal_source(t)


def static_data_to_authenticate(s: Session) -> bytes:
    if s.db.get(0xDF00):
        raise oda.OdaError("record used for ODA is not in a 70 template")
    return bytes(s.static_data) + oda.sda_tag_list_data(s.db.get(0x9F4A), s.db)


def check_mandatory(s: Session, tags: list[int]) -> None:
    missing = [t for t in tags if t not in s.db]
    if missing:
        raise CardError("mandatory data missing: " + ",".join(f"{t:X}" for t in missing))


# --- ODA key chain ---------------------------------------------------------------------

def retrieve_issuer_pk(s: Session) -> oda.PublicKey:
    rid = (s.db.get(0x4F) or s.db.get(0x84) or b"")[:5]
    idx = s.db.get(0x8F)
    if not idx or 0x90 not in s.db or 0x9F32 not in s.db or 0x5A not in s.db:
        raise oda.OdaError("issuer certificate data missing")
    capk = s.env.capks.find(rid, idx[0], s.txn.date)
    if capk is None:
        raise oda.OdaError("CA public key not found")
    return oda.recover_issuer_pk(capk, s.db[0x90], s.db.get(0x92), s.db[0x9F32], s.db[0x5A],
                                 s.txn.date, s.env.capks)


def retrieve_icc_pk(s: Session, issuer: oda.PublicKey | None = None) -> oda.PublicKey:
    issuer = issuer or retrieve_issuer_pk(s)
    if 0x9F46 not in s.db or 0x9F47 not in s.db:
        raise oda.OdaError("ICC certificate data missing")
    return oda.recover_icc_pk(issuer, s.db[0x9F46], s.db.get(0x9F48), s.db[0x9F47],
                              static_data_to_authenticate(s), s.db[0x5A], s.txn.date)


# --- Processing restrictions (Book 3 10.4) ---------------------------------------------

def processing_restrictions(s: Session) -> None:
    db, term = s.db, s.env.terminal
    if 0x9F08 in db and db[0x9F08] != db[0x9F09]:
        s.set_tvr(TVR_APP_VERSION_DIFFERS)
    auc = db.get(0x9F07)
    if auc and len(auc) >= 2:
        ttype = s.txn.type
        is_atm = (term.terminal_type & 0x0F) in (4, 5, 6) and term.terminal_type >> 4 == 1 \
            and bit(term.additional_capabilities, 1, 8)
        if (is_atm and not bit(auc, 1, 2)) or (not is_atm and not bit(auc, 1, 1)):
            s.set_tvr(TVR_SERVICE_NOT_ALLOWED)
        if 0x5F28 in db:
            domestic = db[0x5F28] == term.country_code
            if ttype in (0x01, 0x17):  # cash
                if not bit(auc, 1, 8 if domestic else 7):
                    s.set_tvr(TVR_SERVICE_NOT_ALLOWED)
            elif ttype in (0x00, 0x09):  # purchase (goods or services)
                if not (bit(auc, 1, 6) or bit(auc, 1, 4)) if domestic else not (bit(auc, 1, 5) or bit(auc, 1, 3)):
                    s.set_tvr(TVR_SERVICE_NOT_ALLOWED)
                if ttype == 0x09 and not bit(auc, 2, 8 if domestic else 7):
                    s.set_tvr(TVR_SERVICE_NOT_ALLOWED)
    today = _yymmdd(s.txn.date)
    if 0x5F25 in db and _yymmdd(db[0x5F25].hex()) > today:
        s.set_tvr(TVR_NOT_EFFECTIVE)
    if 0x5F24 in db and _yymmdd(db[0x5F24].hex()) < today:
        s.set_tvr(TVR_EXPIRED)
    pan = db.get(0x5A)
    if pan and pan.hex().upper().rstrip("F").encode() in term.exception_file:
        s.set_tvr(TVR_EXCEPTION_FILE)


def _yymmdd(d: str) -> int:
    if len(d) != 6 or not d.isdigit():
        raise CardError(f"invalid date {d}")
    yy = int(d[:2])
    return (2000 + yy if yy < 50 else 1900 + yy) * 10000 + int(d[2:6])


# --- Cardholder verification (Book 3 10.5, Book 4 6.3) ---------------------------------

CVM_FAIL = 0x00
CVM_PLAINTEXT_PIN = 0x01
CVM_ONLINE_PIN = 0x02
CVM_PLAINTEXT_PIN_SIG = 0x03
CVM_ENC_PIN = 0x04
CVM_ENC_PIN_SIG = 0x05
CVM_SIGNATURE = 0x1E
CVM_NO_CVM = 0x1F
CVM_CDCVM = 0x20  # Mastercard Book C-2 private use (confirmation code verified)

RESULT_UNKNOWN, RESULT_FAILED, RESULT_SUCCESS = 0, 1, 2


@dataclass
class CvmOutcome:
    results: bytes           # 9F34
    signature: bool = False
    online_pin: bool = False
    offline_pin: bool = False
    cdcvm: bool = False


def condition_satisfied(cond: int, s: Session, x: int, y: int, supported: Callable[[int], bool], method: int) -> bool:
    ttype, amount = s.txn.type, s.txn.amount
    same_ccy = s.db.get(0x9F42) == s.txn.currency_code
    unattended = not s.env.terminal.attended
    if cond == 0x00:
        return True
    if cond == 0x01:
        return unattended and ttype == 0x01
    if cond == 0x02:
        return ttype not in (0x01, 0x09, 0x17) and s.txn.amount_other == 0
    if cond == 0x03:
        return supported(method)
    if cond == 0x04:
        return not unattended and ttype in (0x01, 0x17)
    if cond == 0x05:
        return ttype == 0x09 or s.txn.amount_other > 0
    if cond in (0x06, 0x07, 0x08, 0x09):
        if not same_ccy:
            return False
        limit = x if cond in (0x06, 0x07) else y
        return amount < limit if cond in (0x06, 0x08) else amount > limit
    return False


def terminal_supports_cvm(caps: bytes, method: int) -> bool:
    m = method & 0x3F
    return {
        CVM_PLAINTEXT_PIN: bit(caps, 2, 8),
        CVM_ONLINE_PIN: bit(caps, 2, 7),
        CVM_PLAINTEXT_PIN_SIG: bit(caps, 2, 8) and bit(caps, 2, 6),
        CVM_ENC_PIN: bit(caps, 2, 5),
        CVM_ENC_PIN_SIG: bit(caps, 2, 5) and bit(caps, 2, 6),
        CVM_SIGNATURE: bit(caps, 2, 6),
        CVM_NO_CVM: bit(caps, 2, 4),
        CVM_FAIL: True,
    }.get(m, False)


KNOWN_CVMS = {CVM_FAIL, CVM_PLAINTEXT_PIN, CVM_ONLINE_PIN, CVM_PLAINTEXT_PIN_SIG, CVM_ENC_PIN,
              CVM_ENC_PIN_SIG, CVM_SIGNATURE, CVM_NO_CVM}


def cvm_list_processing(s: Session, caps: bytes,
                        perform: Callable[[int], int]) -> CvmOutcome:
    """Walk the CVM List. `perform(method)` executes a PIN method and returns RESULT_*.

    Signature and online PIN are recorded without card interaction. The caller supplies the
    PIN handling (offline PIN for contact; contactless kernels never pass offline PIN).
    """
    aip = s.db.get(0x82, b"\x00\x00")
    if not bit(aip, 1, 5):
        return CvmOutcome(bytes.fromhex("3F0000"))
    cvm_list = s.db.get(0x8E)
    if not cvm_list or len(cvm_list) < 10:
        s.set_tvr(TVR_ICC_DATA_MISSING)
        return CvmOutcome(bytes.fromhex("3F0000"))
    x, y = int.from_bytes(cvm_list[0:4], "big"), int.from_bytes(cvm_list[4:8], "big")
    rules = [cvm_list[i:i + 2] for i in range(8, len(cvm_list) - 1, 2)]
    sup = lambda m: terminal_supports_cvm(caps, m)  # noqa: E731
    last_failed: bytes | None = None
    for rule in rules:
        method, cond = rule[0], rule[1]
        code = method & 0x3F
        apply_next = bool(method & 0x40)
        if not condition_satisfied(cond, s, x, y, sup, method):
            continue
        if code not in KNOWN_CVMS:
            s.set_tvr(TVR_UNRECOGNISED_CVM)
            if apply_next:
                continue
            break
        if code == CVM_FAIL:
            break
        if not sup(code):
            if apply_next:
                continue
            break
        out = _perform_cvm(s, code, rule, perform)
        if out is not None:
            return out
        last_failed = rule
        if apply_next:
            continue
        s.set_tvr(TVR_CVM_FAILED)
        return CvmOutcome(rule + bytes([RESULT_FAILED]))
    else:
        # list exhausted: report the last CVM attempted, or "no CVM performed"
        s.set_tvr(TVR_CVM_FAILED)
        return CvmOutcome((last_failed or b"\x3F\x00") + bytes([RESULT_FAILED]))
    s.set_tvr(TVR_CVM_FAILED)
    return CvmOutcome(rule + bytes([RESULT_FAILED]))


def _perform_cvm(s: Session, code: int, rule: bytes, perform: Callable[[int], int]) -> CvmOutcome | None:
    if code == CVM_NO_CVM:
        return CvmOutcome(rule + bytes([RESULT_SUCCESS]))
    if code == CVM_SIGNATURE:
        return CvmOutcome(rule + bytes([RESULT_UNKNOWN]), signature=True)
    if code == CVM_ONLINE_PIN:
        res = perform(code)
        if res == RESULT_FAILED:
            return None
        s.set_tvr(TVR_ONLINE_PIN)
        return CvmOutcome(rule + bytes([RESULT_UNKNOWN]), online_pin=True)
    # offline PIN variants
    res = perform(code)
    if res == RESULT_SUCCESS:
        sig = code in (CVM_PLAINTEXT_PIN_SIG, CVM_ENC_PIN_SIG)
        return CvmOutcome(rule + bytes([RESULT_UNKNOWN if sig else RESULT_SUCCESS]),
                          signature=sig, offline_pin=True)
    return None


# --- Terminal risk management (Book 3 10.6) --------------------------------------------

def terminal_risk_management(s: Session, *, floor_limit: int | None = None, velocity: bool = True) -> None:
    cfg, amount = s.aid_cfg, s.txn.amount
    floor = cfg.floor_limit if floor_limit is None else floor_limit
    if amount >= floor:
        s.set_tvr(TVR_FLOOR_LIMIT)
    # random transaction selection
    if s.env.terminal.online_capable and amount < floor and cfg.target_percent:
        rnd = int.from_bytes(s.env.rng(1), "big") % 99 + 1
        if amount < cfg.threshold:
            pct = cfg.target_percent
        else:
            span = max(floor - cfg.threshold, 1)
            pct = cfg.target_percent + (cfg.max_target_percent - cfg.target_percent) * (amount - cfg.threshold) // span
        if rnd <= pct:
            s.set_tvr(TVR_RANDOM_ONLINE)
    # velocity checking
    if velocity and 0x9F14 in s.db and 0x9F23 in s.db:
        atc = _get_data(s, 0x9F36)
        last = _get_data(s, 0x9F13)
        if atc is None or last is None:
            s.set_tvr(TVR_LCOL_EXCEEDED)
            s.set_tvr(TVR_UCOL_EXCEEDED)
            s.set_tvr(TVR_ICC_DATA_MISSING)
        else:
            a, l_ = int.from_bytes(atc, "big"), int.from_bytes(last, "big")
            if a <= l_:
                s.set_tvr(TVR_LCOL_EXCEEDED)
                s.set_tvr(TVR_UCOL_EXCEEDED)
            else:
                if a - l_ > (s.db[0x9F14] or b"\x00")[0]:
                    s.set_tvr(TVR_LCOL_EXCEEDED)
                if a - l_ > (s.db[0x9F23] or b"\x00")[0]:
                    s.set_tvr(TVR_UCOL_EXCEEDED)
            if l_ == 0:
                s.set_tvr(TVR_NEW_CARD)
    s.set_tsi(TSI_TRM)


def _get_data(s: Session, tag: int) -> bytes | None:
    r = s.chan.exchange(apdu.get_data(tag))
    if not r.ok:
        return None
    n = tlv.find(r.data, tag) if r.data else None
    if n is not None:
        s.db[tag] = n.value
    return n.value if n else None


# --- Terminal action analysis (Book 3 10.7) --------------------------------------------

def _hit(tvr: bytes, *masks: bytes) -> bool:
    return any(t & m for mask in masks for t, m in zip(tvr, mask))


def terminal_action_analysis(s: Session, tac_denial: bytes, tac_online: bytes, tac_default: bytes,
                             online_capable: bool) -> int:
    """Return the cryptogram type to request: apdu.AAC / apdu.TC / apdu.ARQC."""
    s.sync()
    tvr = bytes(s.tvr)
    iac_denial = s.db.get(0x9F0E, bytes(5))
    iac_online = s.db.get(0x9F0F, b"\xFF" * 5)
    iac_default = s.db.get(0x9F0D, b"\xFF" * 5)
    if _hit(tvr, iac_denial, tac_denial):
        return apdu.AAC
    if s.txn.force_online and online_capable:
        s.set_tvr(TVR_MERCHANT_FORCED_ONLINE)
        return apdu.ARQC
    if online_capable:
        return apdu.ARQC if _hit(tvr, iac_online, tac_online) else apdu.TC
    return apdu.AAC if _hit(tvr, iac_default, tac_default) else apdu.TC


def default_action(s: Session, tac_default: bytes) -> int:
    """Book 3 10.7: the decision when the terminal cannot go online."""
    s.sync()
    return apdu.AAC if _hit(bytes(s.tvr), s.db.get(0x9F0D, b"\xFF" * 5), tac_default) else apdu.TC


def cryptogram_type(cid: bytes | None) -> int:
    return (cid[0] & 0xC0) if cid else -1


def parse_generate_ac(rsp: bytes, db: TLVDatabase) -> list[tlv.TLV]:
    nodes = tlv.parse(rsp)
    if len(nodes) != 1:
        raise CardError("GENERATE AC response is not a single template")
    n = nodes[0]
    if n.tag == 0x80:
        v = n.value
        if len(v) < 11:
            raise CardError("GENERATE AC format 1 too short")
        db[0x9F27], db[0x9F36], db[0x9F26] = v[0:1], v[1:3], v[3:11]
        if len(v) > 11:
            db[0x9F10] = v[11:]
        return []
    if n.tag == 0x77:
        db.store_card_data(n.children)
        if not db.get(0x9F27) or 0x9F36 not in db:
            raise CardError("GENERATE AC response missing CID or ATC")
        return n.children
    raise CardError("unexpected GENERATE AC template")


def kernel_amount_digits(s: Session) -> int:
    return bcd_to_int(s.db.get(0x9F02, b"\x00"))
