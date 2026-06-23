# Security Gate 3 — Cycle 6 (failed-tx receipts, on-chain contract text, vouch UX)

- **Branch / commit:** `feat/cycle6-contracts-vouch-docs` @ `d6cbbe5`
- **Scope:** the cycle-6 diff over M1–M4 + cycle 5 — (1) failed-tx mined as `status: 0x0` receipts;
  (2) full NL contract text stored on-chain via `deployContract(string text, address[])`; (3) the
  `p.nonce + 1` failed-tx nonce SET; (4) regression on cycle-5 oracle-admin / escrow defenses.
- **Method:** static audit of the diff + **live PoCs on `:38545`** (`crates/rpc/tests/sec_c6_poc.rs`,
  5 tests, all green). Node booted on the non-default security port and torn down after; no listeners
  left bound.
- **Verdict: FAIL** — one **High** finding open (C6-SEC-1, unbounded contract-text DoS). All other
  vectors (failed-tx griefing economics, nonce/replay, prompt-injection regression, escrow least-
  authority) are clean.

---

## Findings

### C6-SEC-1 — Unbounded contract-text storage / mempool DoS (flat fee, no size bound) — **HIGH**  [OPEN]

**What.** `deployContract(string text, address[] parties)` carries the **full** NL text in calldata,
into the mempool, and into permanent on-chain state (`PromptContract.text`) with **no size limit
anywhere** and a **flat fee** (`GAS_CONTRACT = 120_000` gas ⇒ `fee_for_gas(GAS_CONTRACT) = 1.2e14`
base units = **0.00012 UBI**) that is **independent of `text.len()`**. The marginal cost of storing a
byte of permanent on-chain state is therefore **zero**.

Audit confirmed there is no bound in the path:
- `ingest_raw_tx` (`crates/rpc/src/lib.rs:1980`) parses the full string and pushes it to an **unbounded
  in-memory mempool** (`g.mempool.push`, `lib.rs:2078`); the submit gate checks only fee affordability
  and nonce, never text size or mempool depth.
- `parse_calldata` (`crates/rpc/src/contracts.rs:134`) ABI-decodes the whole `string` with no length
  guard.
- `deploy_contract` (`crates/runtime/src/contracts.rs:594`) validates only `parties.is_empty()` — no
  bound on `text` **or** on `parties`. The record is inserted into the never-pruned `contracts` HashMap.
- `gas_for_kind` (`lib.rs:104`) returns the constant `GAS_CONTRACT` for `DeployContract` regardless of
  payload size — so a 1-byte text and a 5 MB text pay the **same** fee.

**Economics (why this is High, not Low).** A single verified human earns 1 UBI/hour. At 0.00012 UBI per
deploy that is ~**8,300 deploys/hour from emission alone**. The only per-tx ceiling is jsonrpsee's
default 10 MB request body (no override in `Server::builder()`, `lib.rs:3478`), i.e. ~5 MB of usable
`text` per tx. That is on the order of **tens of GB/hour of permanent, un-prunable state and per-block
RAM** per single sybil-free identity, paid entirely from streaming UBI. Multiple identities or a funded
attacker multiply it. `parties: address[]` is a secondary (smaller) amplifier — also unbounded, and
`O(n log n)` sorted+deduped per deploy in `PromptContract::new`.

**PoC (live, `:38545`).** `crates/rpc/tests/sec_c6_poc.rs`:
- `poc_unbounded_contract_text_dos` — a **1 MB** text deploy is accepted, mined `status: 0x1`, the full
  1,000,000-byte text reads back verbatim via `ubi_getContract`, and the TREASURY is credited exactly
  `fee_for_gas(GAS_CONTRACT)` — i.e. the **flat** fee, identical to a 10-byte contract.
- `poc_mempool_text_amplification` — 8 × 200 KB deploys (~1.6 MB) all admitted into the mempool with
  no depth/byte cap and all mined into one block.

**Remediation (any one closes it; recommend the first two together).**
1. **Hard size cap.** Reject at submit (and re-check in the runtime) when `text.len()` exceeds a bound
   (e.g. 4–8 KB — generous for an NL agreement). Add `CalldataError::TextTooLarge` and check it in
   `parse_calldata` / `ingest_raw_tx` so the wallet gets a synchronous error. Apply the same to a
   `parties` count cap.
2. **Fee-by-size.** Charge gas proportional to `text.len()` (and parties count) so on-chain storage has
   a real, scaling cost — `gas = GAS_CONTRACT + k * text.len()`. This makes bulk-storage attacks pay
   linearly and keeps the submit-gate affordability check honest. Thread the size into `gas_for_kind`
   for `DeployContract` (it currently ignores the payload).
3. **Bound the mempool / per-block byte budget** (defense-in-depth): cap total queued bytes and total
   bytes mined per block so a burst cannot spike RAM before a fee even settles.

> The `text_ref = keccak256(text)` commitment is unchanged and fine; the issue is purely the absence of
> a size bound + the flat fee, not the hashing.

---

### C6-SEC-2 — Failed-tx griefing economics — **acceptable as designed** (Info, no action)

A queued op that fails at block time is now mined as a `status: 0x0` tx. Assessed for cheap-spam /
state-bloat / mis-charge:
- **Cost is real.** The full per-kind gas fee is charged on a failed tx (`charge_fee` runs before the
  apply match; the failure arm keeps it). `poc_failed_tx_charges_fee_bounded_reason_no_partial_state`
  confirms the TREASURY is credited `fee_for_gas(GAS_CONTRACT)` on a failed deploy. An attacker pays per
  failed tx exactly as for a successful one — no cheaper than normal spam.
- **The stored `revert_reason` is bounded.** It is the runtime's own `Err` string (e.g. "vouchee has no
  open registration", "no parties"), not attacker-sized input — PoC asserts `< 256` bytes. **One caveat
  that folds into C6-SEC-1:** a failed `deployContract` is still parsed (the failure arm runs *after*
  the `text` was decoded into the mempool), so the **calldata-side** bloat of C6-SEC-1 applies equally
  to deploys that fail. Fixing C6-SEC-1's size cap at submit closes that, since an oversized text would
  be rejected before it is ever mempool'd or mined.
- **No partial state.** A failed op applies no effect — PoC confirms a failed deploy creates **no**
  contract. The only state delta is the fee + the nonce bump, which is the intended EVM-correct
  behavior.

No separate finding: with C6-SEC-1 remediated, failed-tx spam is no cheaper than ordinary tx spam and
carries only a small bounded reason string.

---

### C6-SEC-3 — Nonce / replay on the `p.nonce + 1` SET — **PASS**

The failed-tx arm sets `acct.nonce = p.nonce + 1` (rather than `+= 1`) to stay idempotent across the
two op shapes (hub ops bump the nonce in `consume_nonce` *before* erroring; `apply_transfer` /
`fund_contract` validate-before-mutate and leave it unbumped on `Err`). Verified this is the **unique
correct post-state** under the FIFO mempool + sequential-nonce submit gate, for both single- and
multi-tx-per-sender-per-block ordering, on both op shapes (no skip — it never lands on `+2`; no
double-bump). `poc_failed_tx_nonce_no_replay_no_skip` confirms live: a failed deploy advances the chain
nonce exactly 0→1; **resending the identical raw tx is rejected** ("nonce too low" — no replay); and the
next tx at nonce 1 succeeds (no gap). EIP-155 chain-id binding + signature recovery (the existing replay
protections) are unchanged.

---

### C6-SEC-4 — Regression: prompt-injection fencing on stored text + escrow least-authority — **PASS**

- **Injection fencing intact.** The interpreter now reads `contract.text` (stored on-chain) instead of
  a derived stand-in, but it is fed through the **same** `contract_prompt::frame()` untrusted-data
  fence (`crates/oracle/src/contract_prompt.rs`): the text is wrapped in labeled UNTRUSTED markers, the
  closing marker is defanged (`DATA_CLOSE → [redacted-marker]`), and the pinned system prompt declares
  the contract text non-instruction. `poc_stored_injection_text_is_inert_data` deploys a contract whose
  text contains a jailbreak payload *and a forged `<<<UBI2_UNTRUSTED_CONTRACT_END>>>` marker*; it is
  stored verbatim (transparency) but remains inert DATA, and the runtime escrow cap independently
  re-checks every op (the cycle-4/5 defense-in-depth). Storing attacker text on-chain does not change
  its trust classification.
- **Cycle-5 defenses untouched.** `git diff 458f552..d6cbbe5` shows `crates/oracle/src/url_policy.rs`,
  `crates/rpc/src/oracle_admin.rs`, `crates/node/src/oracle_cfg.rs`, `crates/runtime/src/lifecycle.rs`,
  and `crates/runtime/src/humanity.rs` are **not modified** by cycle 6 — the oracle-admin Host-pinning /
  Origin-allowlist / base_url SSRF policy and the escrow/least-authority + party-only-refund validation
  are byte-for-byte intact. `resolve_case` gained only `block`/`resolved_at` plumbing; the authority
  validation in `apply_effect` is unchanged.

---

## Tests / checks run

- `cargo test -p ubi2-rpc --test sec_c6_poc` — **5/5 green** (the live PoCs above, on `:38545`/`:38546`
  …`:38549`).
- `cargo test -p ubi2-rpc --test c6_failed_tx` — 3/3 green (cycle-6 failed-tx regression unaffected).
- `cargo fmt` clean on the new file; `cargo clippy -p ubi2-rpc --tests` — no warnings from
  `sec_c6_poc` (the 3 pre-existing `c6_qa` doc-comment lints are unrelated to this gate).

## Gate decision

**FAIL.** C6-SEC-1 (unbounded contract-text DoS) is an open High. Remediate with a `text` (and
`parties`) size cap at submit + fee-by-size, then re-run `sec_c6_poc` (the DoS PoC should flip to a
rejected-at-submit assertion) to clear the gate. All other cycle-6 vectors pass.
