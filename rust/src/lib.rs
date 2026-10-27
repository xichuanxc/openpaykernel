//! # OpenPayKernel: an open-source EMV Level 2 kernel (contact and contactless)
//!
//! **STUDY / RESEARCH USE ONLY.** Not certified by EMVCo or any payment brand, not
//! security-audited, not guaranteed to be bug-free, and provided "AS IS" without warranty
//! (Apache-2.0). Do not use it to process real payments. See the Disclaimer in README.md.
//!
//! This crate is the Rust implementation, alongside the Python reference and the C library
//! in the same repository. All three are checked against the same APDU-transcript
//! conformance vectors (`conformance/vectors`).
//!
//! * `#![no_std]` + `alloc`, no dependencies (own SHA-1 and RSA).
//! * Hardware enters only through [`apdu::Reader`]: `transmit(C-APDU) -> R-APDU`.
//!
//! ```
//! use openpaykernel::{apdu::TransmissionError, AidConfig, CapkStore, Environment, EntryPoint,
//!                     MastercardKernel, TerminalConfig, Transaction, VisaKernel};
//!
//! let mut visa = AidConfig::new(&[0xA0, 0, 0, 0, 0x03, 0x10, 0x10]);
//! visa.kernel_id = 3;
//! let env = Environment::new(TerminalConfig::default(), vec![visa], CapkStore::new(),
//!                            Box::new(|buf: &mut [u8]| buf.fill(0x11)));
//! let mut ep = EntryPoint::new(env, vec![Box::new(VisaKernel), Box::new(MastercardKernel)]);
//!
//! // A "reader" with no card in the field: every command fails at Level 1.
//! let mut reader = |_capdu: &[u8]| -> Result<Vec<u8>, TransmissionError> { Err(TransmissionError) };
//! let outcome = ep.process(&mut reader, &Transaction::new(100), None);
//! assert_eq!(outcome.status, openpaykernel::Status::TryAgain);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod apdu;
pub mod capk;
pub mod config;
pub mod contact;
pub mod crypto;
pub mod dol;
pub mod emvproc;
pub mod entry_point;
pub mod kernels;
pub mod oda;
pub mod outcome;
pub mod tags;
pub mod tlv;

pub use capk::{Capk, CapkStore};
pub use config::{AidConfig, Environment, TerminalConfig, Transaction};
pub use contact::{AppCandidate, ContactHost, ContactKernel, ContactResult, OnlineResponse};
pub use entry_point::{ContactlessKernel, EntryPoint};
pub use kernels::{
    amex::AmexKernel, discover::DiscoverKernel, jcb::JcbKernel, mastercard::MastercardKernel, unionpay::UnionPayKernel,
    visa::VisaKernel,
};
pub use outcome::{Cvm, Outcome, Status};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
