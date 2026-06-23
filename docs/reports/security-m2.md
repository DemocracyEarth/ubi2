# Security review — M2 (Streaming primitive + Stream NFTs)

**Gate:** Definition-of-Done GATE 3 (security) · **Task:** M2-T7
**Reviewer:** security-engineer (authorized defender/red-team, this project only)
**Date:** 2026-06-21
**Scope:** M2 diff — `crates/runtime/src/lib.rs` (stream ops: open/settle/stop, deposit lock, integer
math), `crates/rpc/src/lib.rs` (StreamHub dispatch in `eth_sendRawTransaction`, ERC-721 precompile in
`eth_call`), `crates/rpc/src/streams.rs` (calldata ABI, token-id flag math, tokenURI SVG/JSON
generation), `packages/sdk/src/streaming.ts`.
**Devnet under test:** single node, `UBI2_RPC_ADDR=127.0.0.1:38545`, chainId `0x5542` (21826),
1 s block tick. Txs signed with the well-known PUBLIC Hardhat/Anvil account #0 (the seeded dev account)
and freshly-generated throwaway keys, via `viem` over the real JSON-RPC wire path.

## Verdict: **PASS**

**No open High/Critical findings on the M2 diff.** The four invariants that would gate a FAIL —
**stream solvency** (a stream never pays out more than its deposit), **deposit conservation** (no
double-spend, no refund inflation), **soulbound enforcement** (transfer/approve revert), and
**signature/replay integrity** (EIP-155 + nonce) — all **held under live attack**. Every over-draw,
double-spend, double-stop, malformed-calldata, overflow, and injection attempt was rejected or clamped,
and the runtime (the authority) re-validates and fails closed at block time on every op.

The remaining findings are Medium/Low hardening + spec-conformance items appropriate to defer on a
localhost single-node devnet. The Medium (M2-F1, unbounded stream registry) is the same class as the
already-tracked cycle-1 **FU-1** mempool item and inherits its deferral rationale.

---

## Threat model (M2 streaming surface)

| Surface | Attacks considered | Assessment |
|---|---|---|
| **Stream economics** | over-draw / insolvency (pay > deposit), deposit double-spend (lock same balance into N streams), stop/refund inflation, rate abuse, `rate*elapsed` overflow | **Solid for integrity.** Solvency is structural (D1): `accrued = min(rate*elapsed, deposit)` with saturating math. `open_stream` settles → checks `settled_balance ≥ deposit` → debits, all on a copy, fail-closed. `stop_stream` pays accrued then refunds `deposit − drawn`; double-stop blocked by `NotActive`. Conservation verified live to the base unit (PoC E). One admission-layer defect (M2-F1) that the runtime catches at block time — does **not** break integrity. |
| **Calldata parsing** | truncated/malformed args, unknown selectors, wrong-length tail, u128-overflowing `uint256` args, `>u64` stream id, `value!=0` on stream tx | **Robust.** `parse_calldata` distinguishes TooShort / UnknownSelector / BadArgs / Overflow / Soulbound; every malformed input rejected cleanly with a precise error (PoC B). One spec-conformance gap: a non-zero tx `value` is silently coerced to 0 rather than rejected (M2-F3, Low). |
| **Soulbound NFTs** | bypass transfer/approve via raw tx or `eth_call` simulation | **Enforced both paths.** `transferFrom`/`safeTransferFrom`/`approve`/`setApprovalForAll` selectors → `CalldataError::Soulbound` → revert (code 3) in `eth_sendRawTransaction`; `erc721_call` reverts the same in `eth_call`. There is no transfer/approve state to corrupt. Verified live (PoC B2/B4). |
| **tokenURI / SVG / JSON injection** | markup/script injection via interpolated fields; oversized output; `ownerOf`/`tokenURI` of garbage/nonexistent/flag-edge tokenIds | **No injection vector.** Every interpolated field is node-formatted hex (addresses), an integer, or a fixed status label — none attacker-controlled free text — and `xml_escape`/`json_escape` are applied defensively. Output is small (~5 KB), JSON parses, SVG well-formed (PoC C). Garbage/nonexistent/stray-bit tokenIds revert cleanly; `decode_token_id` rejects ids with bits set between 64 and 254. |
| **Integer safety** | u128/u256 overflow in accrual, deposit lock, rate, `t_end`, tokenId flag math | **Safe by construction.** `MAX_RATE * u64::MAX` and `MAX_RATE * (a century)` both fit in u128 with margin; `accrued` clamps with `.min(deposit)` regardless. RPC pre-rejects u128-overflowing `uint256` args; runtime rejects `rate > MAX_RATE`. `t_end`'s `as u64` truncation only ever *shrinks* the accrual window (under-pays, never over-pays) — solvency unaffected; the deposit cap is the load-bearing bound. |
| **Replay / signature / chainId** | replay a stream tx, wrong-chain tx, forged signer, nonce reuse/gap | **Held.** Stream-op txs go through the same `decode_2718` → EIP-155 chainId binding → `recover_signer` path as transfers, then `consume_nonce` enforces + bumps the sender nonce at block time (mirrors `apply_transfer`). Wrong-chain and pre-155 txs rejected (inherited M1 path, still covered). |
| **Griefing / DoS** | open many streams (unbounded registry + per-account index), tiny-deposit spam | **Medium (M2-F1).** No per-account / global cap on streams; gas not charged (documented deviation) so admission is free. Localhost single-node → Medium, same as FU-1. |

### Documented M2 deviations — security impact (intended, not bugs)
- **Gas not charged.** No economic anti-spam cost → amplifies the unbounded-registry vector (M2-F1).
  Acceptable on devnet; revisit before any shared/multi-node deployment (tracked under FU-1).
- **`eth_call` minimal except the StreamHub ERC-721 precompile.** The precompile is read-only (view
  methods) and soulbound mutators revert — no contract-execution / reentrancy surface introduced.
- **Soulbound NFTs (no transfer/approve state in M2).** Reduces attack surface — verified enforced.
- **Balance evaluated at wall-clock `now`.** Inherited M1 behavior; not an M2 security issue.

---

## Findings (ranked by severity)

| # | Severity | Finding | Status |
|---|---|---|---|
| M2-F1 | Medium | Unbounded stream registry + per-account index — no cap on open streams; free (gas-less) admission | Open (defer — same class as FU-1) |
| M2-F2 | Medium | Stream-open mempool over-admission: N opens against the same balance all admitted (runtime drops the excess at block time) | **Fixed** — cumulative per-sender pending-commitment check added at submit (`spendable_debit`); regression test `second_full_balance_open_rejected_at_admission` |
| M2-F3 | Low | Non-zero tx `value` on a StreamHub op is silently coerced to 0, not rejected (spec D2/Q1 says value must be 0) | Open (defer) |
| M2-F4 | Info | `openStream` to the zero address is allowed (deposit drips to an unspendable address — a self-inflicted burn) | Open (defer / optional reject) |

**No High/Critical.** Solvency, deposit conservation, refund correctness, soulbound enforcement, and
signature/replay integrity all held. M2-F1/F2 are pre-mainnet hardening that inherit FU-1's deferral
(localhost single-node devnet); they do **not** affect fund integrity.

---

### M2-F1 — Unbounded stream registry / free stream spam (Medium)

**Where:** `crates/runtime/src/lib.rs` `MemState.streams` + `outgoing`/`incoming` index `Vec`s
(no bound); `crates/rpc/src/lib.rs` `Inner.mempool` (no cap, inherited). Gas not charged.

**Repro (PoC D4, live):** one funded sender pushed 25 `openStream` txs (1-wei deposit, rate 1) with
sequential nonces in a single tick window; **all 25 were admitted and mined**, leaving the account with
26 outgoing streams. With unlimited fresh keys and gas-less admission, the stream registry and the
per-account index `Vec`s grow without bound; `ubi_getStreams(addr)` then returns an unbounded list.

**Impact:** Memory growth and `ubi_getStreams` / `nft_balance_of` response size scale with attacker
volume. Localhost single-node devnet → **Medium**, consistent with the cycle-1 deferral of FU-1.

**Remediation:** Add a per-account open-stream cap and a global registry bound; reject opens past the
cap (`-32005`-style "too many streams"). Bundle with FU-1's per-sender / global mempool caps. Before
any shared deployment, charge nominal gas or add a per-IP rate limit so admission isn't free.

---

### M2-F2 — Stream-open mempool over-admission (Medium)

**Where:** `crates/rpc/src/lib.rs` `ingest_raw_tx` (the `OpenStream` deposit-affordability check,
~lines 758–764). The submit-time check compares each open's `deposit` against the sender's *current*
live balance only; it counts pending txs in the nonce (`expected_nonce`) but **not** the cumulative
pending deposit. So N sequential-nonce opens, each locking the full balance, all pass admission because
state hasn't advanced between submits.

**Repro (PoC A, live):** dev account holding ~0.00083 UBI; three `openStream` txs (nonces 0–2), each
with `deposit = 90% of balance`, were **all accepted** into the mempool:
```
open #0 nonce=0 -> ACCEPTED 0xafd611b1…
open #1 nonce=1 -> ACCEPTED 0x4f38eaeb…
open #2 nonce=2 -> ACCEPTED 0x83ccfc78…
```
At the next block tick **only open #0 mined** (`status=0x1`, 3 logs — StreamOpened + 2 Transfer mints);
opens #1 and #2 were dropped by the runtime with `insufficient balance for deposit` (a `WARN`, no
receipt). Final state: **exactly one outgoing stream**, sum of locked deposits = one deposit, balance
conserved. **No double-spend** — the runtime's settle-then-check-then-debit on a copy is authoritative
and fails closed.

**Impact:** This is the M2 face of cycle-1 `security-m1` F1 (FU-1). The defect is purely at the
*admission* layer: the mempool advertises opens it cannot honor → silent drops (only a WARN), wasted
block-production cycles, and a misleading "accepted" tx hash returned to the wallet. **Fund integrity
is not affected.**

**Remediation (landed):** `ingest_raw_tx` now sums this sender's still-pending mempool commitments —
each tx's transfer `value` + `openStream` `deposit` + `fundContract` funding, via the `spendable_debit`
helper — and rejects at submit when `live_balance < pending_committed + this_op` (saturating math, so
it fails closed). This mirrors the existing pending-*nonce* accounting and is the FU-1 fix shape
extended to cover the stream-open `deposit`. The PoC-A scenario now rejects the second full-balance
open synchronously with `insufficient balance for deposit … already pending from this sender`.
Regression test: `crates/rpc/tests/m2_acceptance.rs::second_full_balance_open_rejected_at_admission`
(submits two full-balance opens, asserts the second is rejected at admission — not silently dropped at
block time — and that exactly one stream mines). Confirmed failing against the pre-fix code.

---

### M2-F3 — Non-zero tx `value` on a StreamHub op silently ignored (Low)

**Where:** `crates/rpc/src/lib.rs` `ingest_raw_tx` — for any non-`Transfer` kind the code sets
`value = 0` (`PendingKind::Transfer { value, .. } => *value, _ => 0`) and never checks that the
submitted envelope value was actually 0. Spec D2/Q1: "`value` on these txs is 0."

**Repro (PoC B3, live):** an `openStream` tx signed with `value = 1000` wei was **accepted and mined**
(`status=0x1`), recorded in the receipt/tx as `value: 0x0`; the recipient was **not** credited the 1000
wei and the sender was **not** debited it (gas-less, so no loss). The value field was silently dropped.

**Impact:** No fund loss or double-spend — the value is discarded, not moved. But the node does not
*enforce* the spec's "value must be 0" rule: a wallet that mistakenly attaches value gets a successful
receipt with the value silently swallowed. Spec-conformance / least-surprise issue. **Low.**

**Remediation:** In `ingest_raw_tx`, reject a StreamHub tx whose envelope `value != 0` with a clear
`-32602` ("StreamHub ops must carry value 0; deposit is a calldata arg") instead of silently coercing.

---

### M2-F4 — `openStream` to the zero address allowed (Info)

**Where:** `crates/runtime/src/lib.rs` `open_stream` validates `from != to`, `rate > 0`, `deposit > 0`,
`rate ≤ MAX_RATE`, but not `to != 0x0`.

**Repro (PoC D3, live):** `openStream(to = 0x000…000, rate 1, deposit 10)` **mined** (`status=0x1`); the
deposit is locked and drips to the unspendable zero address.

**Impact:** None to third parties — the sender burns *its own* collateral by its own choice, matching
Ethereum's "send to 0x0 is allowed" semantics. **Info only.** Optionally reject `to == 0x0` to prevent
accidental burns via a fat-fingered recipient field.

---

## What held (positive assurance)

- **Solvency (criterion 3):** `accrued(now)` capped at `deposit` for all probed timelines incl.
  `now = u64::MAX` and far past `t_end`; saturating `rate*elapsed` then `.min(deposit)`. No over-draw.
- **Deposit conservation / no double-spend (criteria 1–2):** PoC A — N concurrent opens against one
  balance yield exactly one created stream; balance debited by exactly one deposit.
- **Stop/refund conservation (criterion 4):** PoC E — open → accrue → stop conserved
  `sender + recipient + escrow` to the **base unit** (delta = 0); double-stop dropped (`NotActive`),
  balance unchanged → no refund inflation.
- **Soulbound (criterion 7):** PoC B2/B4 — `transferFrom`/`approve` revert (`soulbound`, code 3) as a
  write tx and via `eth_call`.
- **Calldata robustness:** PoC B1 — truncated, unknown-selector, no-args, u128-overflow rate/deposit,
  and `>u64` stream-id calldata all rejected with precise errors.
- **tokenURI/ownerOf edges:** PoC C — nonexistent/stray-bit/max-u256 tokenIds revert; existing tokens
  render valid escaped JSON+SVG (~5 KB), both sides (recipient + sender flag).
- **Replay/chainId:** stream-op nonce enforced+bumped at block time; wrong-chain / pre-155 rejected.
- **No panic / crash:** the node served the entire PoC battery (admission, malformed calldata,
  overflow args, garbage tokenIds, double-stop, griefing) with no panic/abort/overflow in the log.

---

## Pentest transcript (summary)

Harness: `viem`-signed legacy EIP-155 txs over the live JSON-RPC at `127.0.0.1:38545`. PoC scripts were
run from a throwaway harness and removed after; no product code was modified.

| PoC | Attack | Result |
|---|---|---|
| A | 3× `openStream` each locking 90% of balance, sequential nonces, one tick window | 3 admitted, **1 mined**; 2 dropped `insufficient balance for deposit`; one stream, balance conserved — **no double-spend** (→ M2-F2) |
| B1 | truncated / unknown-selector / no-args / 2^200 rate / 2^200 deposit / 2^100 stream-id calldata | all **rejected** with precise `-32602` errors |
| B2 | `transferFrom` as a raw write tx | **reverted** `code=3 "soulbound"` |
| B3 | `openStream` with tx `value = 1000` | accepted, value silently → `0x0`, not credited/debited (→ M2-F3) |
| B4 | `transferFrom` via `eth_call` | **reverted** `code=3 "soulbound"` |
| B5 | value transfer carrying calldata to a non-hub EOA | **rejected** (calldata only for StreamHub) |
| C1 | `ownerOf` of nonexistent / stray-bit / max-u256 / flag-only tokenIds | nonexistent & invalid **revert** `code=3`; valid existing token returns owner |
| C2 | decode `tokenURI(existing)` | valid base64 JSON (parses), inline SVG well-formed, ~5 KB, no `<script`, fields escaped |
| C3 | `tokenURI(id \| SENDER_FLAG)` | renders the Outgoing-side card |
| D1 | `openStream` rate = `MAX_RATE + 1` | admitted, **dropped at block time** (`RateTooHigh`) |
| D2 | self-stream (`to == from`) | admitted, **dropped at block time** (`SelfStream`) |
| D3 | `openStream` to `0x0` | **mined** — allowed (→ M2-F4, Info) |
| D4 | 25× tiny-deposit `openStream` in one window | **25/25 mined**; 26 outgoing streams; unbounded registry (→ M2-F1) |
| E | open → accrue → `stopStream`; then double-stop | conservation delta = **0**; double-stop **dropped** (`NotActive`), balance unchanged — **no refund inflation** |

Integer-safety bounds were checked offline (`MAX_RATE * u64::MAX` and `MAX_RATE * century` fit in u128;
`accrued` clamps to `deposit`; `t_end` truncation only shrinks the window) and corroborated by the
runtime's 20 000-iteration property test (`property_streams_solvent_conserved_reproducible`, GREEN).

Node killed after the run; devnet port released. Report left in the tree (not committed).
