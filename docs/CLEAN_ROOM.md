# How this code was produced

OpenPayKernel is an independent implementation written from the public EMVCo specifications:

* EMV Integrated Circuit Card Specifications for Payment Systems, Books 1–4
* EMV Contactless Specifications for Payment Systems, Book A (Architecture), Book B (Entry Point)
* Book C-2 (Kernel 2) and Book C-3 (Kernel 3)

The project started by studying how existing commercial L2 kernels are structured, using
interoperability analysis of shipped binaries. That analysis was used **only** for
architecture-level questions:

* how a production kernel splits Entry Point, shared EMV processing and per-brand kernels
* what host API shape (init, pre-process, activate, continue, get data) integrators expect
* which Book A structures (outcome, UI request, error indication) are exposed to the host

No decompiled code, data tables, strings or other expression from any third-party binary
was copied into this repository. Every function here was written fresh against the
specification text. The analysis material is excluded from version control (see
`.gitignore`) and must never be added.

## Rules for contributors

1. Implement from the EMVCo specifications (and other public documents). Cite the book and
   section in comments where it helps.
2. Do not contribute code, tables or test data derived from proprietary kernels, vendor
   SDKs, leaked documents or decompiled binaries.
3. Brand-specific test cases must be original. Do not commit certification test tool
   scripts or card images that you are not licensed to redistribute.
4. Never commit real keys. The simulator generates throwaway keys deterministically.
