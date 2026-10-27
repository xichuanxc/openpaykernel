# Architecture

## Layers

```
            ┌───────────────────────────── host application ─────────────────────────────┐
            │  config (terminal, AIDs, CAPKs)   transaction   Reader.transmit()   callbacks │
            └──────────────┬──────────────────────────────┬───────────────────────────────┘
                           │                              │
              contactless  ▼                     contact  ▼
        ┌─────────────────────────┐        ┌─────────────────────────┐
        │ Entry Point (Book B)    │        │ Contact kernel (Book 3) │
        │ pre-processing, PPSE,   │        │ PSE / list of AIDs,     │
        │ candidates, final select│        │ full flow, PIN, online, │
        └──────────┬──────────────┘        │ scripts, 2nd GEN AC     │
                   │ kernel_id             └──────────┬──────────────┘
         ┌─────────┴─────────┐                        │
         ▼                   ▼                        │
  ┌─────────────┐     ┌─────────────┐                 │
  │ Kernel 2 MC │     │ Kernel 3 V  │                 │
  └──────┬──────┘     └──────┬──────┘                 │
         └──────────┬────────┴────────────────────────┘
                    ▼
     ┌──────────────────────────────────────────────────────────┐
     │ emvproc: session, AFL / READ RECORD, processing          │
     │ restrictions, CVM list, TRM, TAA, GEN AC parsing         │
     ├──────────────────────────────────────────────────────────┤
     │ oda: CAPK → issuer PK → ICC PK, SDA/DDA/fDDA/CDA         │
     ├──────────────────────────────────────────────────────────┤
     │ tlv / dol / apdu / data dictionary / SHA-1 / RSA         │
     └──────────────────────────────────────────────────────────┘
```

## Key design decisions

1. **Host I/O goes only through `transmit(C-APDU) → R-APDU`.** The kernel has no hardware
   coupling, so the same code runs against PC/SC, an NFC controller, the simulator, or a
   recorded transcript.
2. **Book A Outcome as the single result type.** Status, Start, CVM, UI request, error
   indication (L1/L2/SW), receipt and field-off are reported the same way by contact and
   contactless kernels. The data record is the transaction's TLV database.
3. **One TLV database per transaction.** Terminal data is loaded first. Card data
   can never overwrite terminal-sourced tags (`store_card_data` / `opk_tlv_store_card` / `TlvDb::store_card_data`),
   and duplicate card data objects in records are rejected.
4. **Kernels are plug-ins** keyed by kernel ID. The Entry Point resolves the ID from
   Kernel Identifier `9F2A` or from the RID default (Book B 3.3.2.5).
5. **The contact kernel uses host callbacks**: `choose_application`, `enter_pin`,
   `go_online`. Contactless kernels need none, because an online request is an Outcome.
6. **The C library has fixed memory.** All buffers are caller-owned or on the stack (around
   4 KB per kernel call), and there is no global mutable state.
7. **Deterministic by injection.** The unpredictable number and every other random value come
   from `Environment.rng` / `opk_env.rng` / the Rust `Environment` RNG closure. This is what
   makes cross-language transcript testing possible.
8. **The Rust crate is memory-safe and portable.** It is `#![no_std]` + `alloc` with
   `#![forbid(unsafe_code)]` and no dependencies. Card data is only read through bounds-checked
   accessors (`get()`, slices validated first), so malformed input becomes a card-data
   outcome, never a panic. Plug-in kernels implement the `ContactlessKernel` trait, and the
   contact kernel is generic over a `ContactHost` implementation.

## Data flow of a contactless transaction

1. `preprocess`: for each AID/kernel combination, check the zero-amount, contactless
   transaction limit, floor limit and CVM limit, then build the Visa TTQ.
2. `SELECT 2PAY.SYS.DDF01`: parse `6F/A5/BF0C/61` entries, match them against the
   combinations, and sort by priority.
3. For each candidate, `SELECT AID` and call `kernel.start(ctx)`. `SELECT_NEXT` moves
   on to the next candidate.
4. The kernel returns an Outcome. `ONLINE_REQUEST` carries the data for the authorisation
   message (field 55).

## Testing strategy

| Layer | Python | C | Rust |
|---|---|---|---|
| Primitives (TLV, DOL, SHA-1, RSA, certificates) | `test_core.py` | `test_core.c` | `tests/core.rs` |
| End-to-end flows vs. simulated cards | `test_kernels.py` (29 scenarios) | — | — |
| Hardware adapter path | `test_hardware_adapter.py` (fake pyscard) | `reader_template` example (CI) | `reader_template` example (CI) |
| Cross-language conformance (byte-exact APDUs) | `gen_vectors.py` generates `conformance/vectors` | `test_vectors.c` replays them all | `tests/conformance.rs` replays them all |
| Robustness against corrupted card data | `test_robustness.py` | `OPK_FUZZ` mode under ASan/UBSan | `OPK_FUZZ` no-panic test |

The simulator (`openpaykernel/sim`) personalises cards with real RSA keys and certificates. The CA
key is 1024-bit and the issuer key is 1024-bit, which forces an issuer PK remainder. The
ICC key is 768-bit, which forces an ICC PK remainder. The simulator computes genuine
SDA/DDA/fDDA/CDA signatures and CDA transaction-data hashes, enforces PIN try counters, and
keeps every response within short-APDU limits. Only the issuer cryptogram itself is a SHA-1
stand-in.
