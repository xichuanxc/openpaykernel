"""Kernel outcome (EMV Contactless Book A, section 6.2), also used by the contact kernel."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Status(IntEnum):
    APPROVED = 0x1
    DECLINED = 0x2
    ONLINE_REQUEST = 0x3
    END_APPLICATION = 0x4
    SELECT_NEXT = 0x5
    TRY_ANOTHER_INTERFACE = 0x6
    TRY_AGAIN = 0x7
    NA = 0xF


class Start(IntEnum):
    A = 0x0
    B = 0x1
    C = 0x2
    D = 0x3
    NA = 0xF


class CVM(IntEnum):
    NO_CVM = 0x0
    SIGNATURE = 0x1
    ONLINE_PIN = 0x2
    CONFIRMATION_CODE_VERIFIED = 0x3
    OFFLINE_PIN = 0x4  # contact only: PIN verified by the ICC
    NA = 0xF


class Message(IntEnum):
    """Book A 7.2 standard message identifiers."""
    APPROVED = 0x03
    NOT_AUTHORISED = 0x07
    ENTER_PIN = 0x09
    PROCESSING_ERROR = 0x0F
    REMOVE_CARD = 0x10
    WELCOME = 0x14
    PRESENT_CARD = 0x15
    PROCESSING = 0x16
    CARD_READ_OK = 0x17
    INSERT_OR_SWIPE = 0x18
    PRESENT_ONE_CARD = 0x19
    APPROVED_SIGN = 0x1A
    AUTHORISING = 0x1B
    INSERT_SWIPE_OR_TRY_ANOTHER = 0x1C
    INSERT_CARD = 0x1D
    SEE_PHONE = 0x20
    PRESENT_CARD_AGAIN = 0x21
    NA = 0xFF


class L1Error(IntEnum):
    OK = 0
    TIMEOUT = 1
    TRANSMISSION = 2
    PROTOCOL = 3


class L2Error(IntEnum):
    OK = 0
    CARD_DATA_MISSING = 1
    CAM_FAILED = 2
    STATUS_BYTES = 3
    PARSING_ERROR = 4
    MAX_LIMIT_EXCEEDED = 5
    CARD_DATA_ERROR = 6
    MAGSTRIPE_NOT_SUPPORTED = 7
    NO_PPSE = 8
    PPSE_FAULT = 9
    EMPTY_CANDIDATE_LIST = 10
    IDS_READ_ERROR = 11
    IDS_WRITE_ERROR = 12
    IDS_DATA_ERROR = 13
    IDS_NO_MATCHING_AC = 14
    TERMINAL_DATA_ERROR = 15


@dataclass
class ErrorIndication:
    l1: L1Error = L1Error.OK
    l2: L2Error = L2Error.OK
    sw12: int = 0
    msg_on_error: Message = Message.NA


@dataclass
class UIRequest:
    message: Message
    status: str = "NOT_READY"  # NOT_READY / IDLE / READY_TO_READ / PROCESSING / CARD_READ_OK / ERROR
    hold_time_ms: int = 0
    value: int | None = None


@dataclass
class Outcome:
    status: Status
    start: Start = Start.NA
    cvm: CVM = CVM.NA
    ui_request: UIRequest | None = None
    ui_on_restart: UIRequest | None = None
    alternate_interface: str | None = None  # 'CONTACT' / 'MAGSTRIPE'
    receipt: bool = False
    field_off_request_ms: int | None = None
    removal_timeout_ms: int = 0
    online_response_data: str | None = None  # 'EMV' / 'ANY' / None
    data_record: dict[int, bytes] = field(default_factory=dict)
    discretionary_data: dict[int, bytes] = field(default_factory=dict)
    error: ErrorIndication = field(default_factory=ErrorIndication)

    def __str__(self) -> str:
        return f"Outcome({self.status.name}, cvm={self.cvm.name}, start={self.start.name})"


def end_application(l2: L2Error = L2Error.OK, sw: int = 0, msg: Message = Message.NA) -> Outcome:
    return Outcome(Status.END_APPLICATION, error=ErrorIndication(l2=l2, sw12=sw, msg_on_error=msg),
                   ui_request=UIRequest(msg, "NOT_READY") if msg != Message.NA else None)


def try_another_interface(msg: Message = Message.INSERT_CARD) -> Outcome:
    return Outcome(Status.TRY_ANOTHER_INTERFACE, alternate_interface="CONTACT",
                   ui_request=UIRequest(msg, "NOT_READY"))


def select_next(l2: L2Error = L2Error.OK, sw: int = 0) -> Outcome:
    return Outcome(Status.SELECT_NEXT, start=Start.C, error=ErrorIndication(l2=l2, sw12=sw))
