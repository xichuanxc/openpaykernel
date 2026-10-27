//! Kernel outcome (EMV Contactless Book A, section 6.2), also used by the contact kernel.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Approved = 1,
    Declined = 2,
    OnlineRequest = 3,
    EndApplication = 4,
    SelectNext = 5,
    TryAnotherInterface = 6,
    TryAgain = 7,
    NotApplicable = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Start {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    NotApplicable = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cvm {
    NoCvm = 0,
    Signature = 1,
    OnlinePin = 2,
    ConfirmationCodeVerified = 3,
    /// Contact only: PIN verified by the ICC.
    OfflinePin = 4,
    NotApplicable = 15,
}

/// Book A 7.2 standard message identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Message {
    Approved = 0x03,
    NotAuthorised = 0x07,
    EnterPin = 0x09,
    ProcessingError = 0x0F,
    RemoveCard = 0x10,
    PresentCard = 0x15,
    Processing = 0x16,
    InsertOrSwipe = 0x18,
    ApprovedSign = 0x1A,
    Authorising = 0x1B,
    InsertSwipeOrTryAnother = 0x1C,
    InsertCard = 0x1D,
    SeePhone = 0x20,
    PresentCardAgain = 0x21,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L1Error {
    Ok = 0,
    Timeout = 1,
    Transmission = 2,
    Protocol = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L2Error {
    Ok = 0,
    CardDataMissing = 1,
    CamFailed = 2,
    StatusBytes = 3,
    ParsingError = 4,
    MaxLimitExceeded = 5,
    CardDataError = 6,
    MagstripeNotSupported = 7,
    NoPpse = 8,
    PpseFault = 9,
    EmptyCandidateList = 10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorIndication {
    pub l1: L1Error,
    pub l2: L2Error,
    pub sw12: u16,
}

impl Default for ErrorIndication {
    fn default() -> Self {
        ErrorIndication { l1: L1Error::Ok, l2: L2Error::Ok, sw12: 0 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub start: Start,
    pub cvm: Cvm,
    pub ui_message: Option<Message>,
    pub receipt: bool,
    pub alternate_interface_contact: bool,
    pub field_off_request_ms: Option<u16>,
    pub error: ErrorIndication,
    /// Transaction data for the authorisation message / receipt (tag → value).
    pub data_record: BTreeMap<u32, Vec<u8>>,
}

impl Outcome {
    pub fn new(status: Status, cvm: Cvm, ui: Option<Message>) -> Self {
        Outcome {
            status,
            start: Start::NotApplicable,
            cvm,
            ui_message: ui,
            receipt: cvm == Cvm::Signature,
            alternate_interface_contact: false,
            field_off_request_ms: None,
            error: ErrorIndication::default(),
            data_record: BTreeMap::new(),
        }
    }

    pub fn end_application(l2: L2Error, sw12: u16, msg: Option<Message>) -> Self {
        let mut o = Outcome::new(Status::EndApplication, Cvm::NotApplicable, msg);
        o.error.l2 = l2;
        o.error.sw12 = sw12;
        o
    }

    pub fn try_another_interface() -> Self {
        let mut o = Outcome::new(Status::TryAnotherInterface, Cvm::NotApplicable, Some(Message::InsertCard));
        o.alternate_interface_contact = true;
        o
    }

    pub fn select_next(l2: L2Error, sw12: u16) -> Self {
        let mut o = Outcome::new(Status::SelectNext, Cvm::NotApplicable, None);
        o.start = Start::C;
        o.error.l2 = l2;
        o.error.sw12 = sw12;
        o
    }

    pub fn try_again_l1(msg: Option<Message>) -> Self {
        let mut o = Outcome::new(Status::TryAgain, Cvm::NotApplicable, msg);
        o.start = Start::B;
        o.error.l1 = L1Error::Transmission;
        o
    }
}
