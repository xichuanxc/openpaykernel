"""Kernel 7: UnionPay qUICS (EMV Contactless Book C-7).

qUICS uses the same quick flow as Visa qVSDC: TTQ in the PDOL, the cryptogram returned
in the GPO response, CTQ-driven CVM, and fDDA over 9F37 || 9F02 || 5F2A || 9F69. This kernel
reuses that engine with a UnionPay profile, and reports the Available Offline Spending
Amount (9F5D) in the data record.

Not implemented: the full UICS (GENERATE AC) fallback flow, SM2/SM3 (domestic) ODA, and
Issuer Update Processing.
Scheme-specific bit assignments follow the public Book C-7 structure but have NOT been
verified against the official specification text.
"""
from __future__ import annotations

from .visa import DATA_RECORD_TAGS, VisaKernel

UNIONPAY_DATA_RECORD_TAGS = DATA_RECORD_TAGS + [0x9F5D, 0x9F69]


class UnionPayKernel(VisaKernel):
    kernel_id = 7
    data_record_tags = UNIONPAY_DATA_RECORD_TAGS
