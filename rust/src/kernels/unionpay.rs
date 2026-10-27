//! Kernel 7: UnionPay qUICS (EMV Contactless Book C-7).
//!
//! qUICS uses the same quick flow as Visa qVSDC (TTQ in the PDOL, cryptogram in the GPO
//! response, CTQ-driven CVM, fDDA). This kernel reuses that engine with a UnionPay profile
//! that also reports the Available Offline Spending Amount (9F5D) and 9F69.
//! Mirrors `python/openpaykernel/kernels/unionpay.py`.
//!
//! Not implemented: the full UICS (GENERATE AC) fallback flow, SM2/SM3 ODA, Issuer Update.
//! Scheme-specific bit assignments have NOT been verified against the official Book C-7 text.

use crate::apdu::TransmissionError;
use crate::entry_point::{ContactlessKernel, KernelContext};
use crate::kernels::visa::start_quick_flow;
use crate::outcome::Outcome;

pub struct UnionPayKernel;

impl ContactlessKernel for UnionPayKernel {
    fn kernel_id(&self) -> u32 {
        7
    }

    fn start(&self, ctx: &mut KernelContext<'_, '_>) -> Result<Outcome, TransmissionError> {
        start_quick_flow(ctx, &[0x9F5D, 0x9F69])
    }
}
