# Security review — M1 (EVM RPC + Wallet)

**Gate:** Definition-of-Done GATE 3 (security) · **Task:** M1-T9
**Reviewer:** security-engineer (authorized defender/red-team, this project only)
**Date:** 2026-06-21
**Scope:** M1 diff — `crates/rpc/src/lib.rs`, `crates/runtime/src/lib.rs`, `crates/node/src/main.rs`, manifests.
**Devnet under test:** single node, `UBI2_RPC_ADDR=127.0.0.1:38545`, chainId `0x5542` (21826).

## Verdict: **PASS**

No open High/Critical findings on the M1 diff. Signature/replay integrity (EIP-155 chain-id
binding, nonce handling) and the balance invariant (I2) **held under attack** — every overdraft,
replay, wrong-chain, malformed, and oversized input was rejected, and no UBI was minted, lost, or
double-spent. The remaining findings are Medium/Low DoS-and-robustness hardening items appropriate
to defer for a local single-node devnet, tracked below.

---

## Threat model (M1 surface)

| Surface | Threat | Assessment |
|---|---|---|
| Tx signature / replay | Cross-chain replay, duplicate-nonce replay, sig malleability | **Mitigated.** alloy `decode_2718` + `recover_signer` verify secp256k1; `chain_id()` is required and must equal `0x5542` (pre-155 unbound txs rejected). Nonce is checked at submit (incl. pending) and re-checked at block time. |
| Balance / transfer math | u128 overflow, over-u128 value, overdraft, double-spend | **Mitigated for fund integrity.** `apply_transfer` settles then validates nonce+balance before any mutation, fails closed (no partial writes), `saturating_*` on emission/credit, U256→u128 guarded. Runtime is the authority and re-validates at block time. One *admission* defect (F1, Medium) — does not break integrity. |
| RPC abuse / DoS | Unbounded mempool, request flooding, oversized bodies | **Partial.** jsonrpsee defaults cap body at 10 MB and connections at ~100; but the mempool is uncapped and a zero-balance sender can admit a valid zero-value tx for free (gas not charged). F2/F3, Medium/Low. |
| Genesis dev key | Real secret leaked / reused with value | **Clean.** It is the well-known public Hardhat/Anvil account #0, clearly marked `PUBLIC, NON-SECRET`. Not a finding. |
| Secret / dependency hygiene | Secrets in code/history, vulnerable deps | **Clean.** No secrets in source or git history; alloy/jsonrpsee/tokio pinned via workspace deps. |

### Documented M1 deviations — security impact (intended, not bugs)
- **Gas not charged.** Removes the economic anti-spam cost → amplifies the mempool-flood vector (F2). Acceptable on devnet; revisit before any shared/multi-node deployment.
- **`eth_call` returns `0x`, no EVM.** No contract execution → no calldata/reentrancy surface in M1. Calldata and contract-creation txs are explicitly rejected (verified).
- **Balance always evaluated at wall-clock `now` (block param ignored).** No historical reconstruction; not a security issue for M1.

---

## Findings (ranked by severity)

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| F1 | Medium | Mempool admits more pending txs than a sender can fund (over-admission) | Open (defer) |
| F2 | Medium | Unbounded mempool — free zero-value tx flood from fresh keys (no gas cost) | Open (defer) |
| F3 | Low | RPC body cap (10 MB default) generous for a tx-only surface; no per-IP rate limit | Open (defer) |
| F4 | Info | `eth_getTransactionCount` ignores the block tag (always latest) | Open (defer) |

No High/Critical. F1–F3 align with the protocol-engineer's flags and are standard pre-mainnet hardening.

---

### F1 — Mempool over-admission (Medium)

**Where:** `crates/rpc/src/lib.rs`, `ingest_raw_tx` (balance check, lines ~459–477).
The submit-time check compares each incoming tx against the sender's *current* balance only; it
accounts for pending txs in the nonce (`expected_nonce` adds mempool count) but **not** in the
balance. So N sequential-nonce txs each spending the full balance all pass admission, because state
hasn't advanced between submits.

**Repro (PoC, from the transcript):** with the dev account holding ~0.0244 UBI, five txs (nonces
1–5) each sending the full ~0.0244 UBI were **all accepted** into the mempool:
```
nonce 1 -> 0x1318ac37...  (accepted)
nonce 2 -> 0xf595c14e...  (accepted)
nonce 3 -> 0x64550a75...  (accepted)
nonce 4 -> 0x0e32a1d3...  (accepted)
nonce 5 -> 0xb4418482...  (accepted)
```
At block time the runtime held the line — only nonce 1 succeeded; the other four were dropped
(`insufficient balance` for #2, nonce-gap for #3–#5). Recipient received exactly **one** transfer's
worth; dev balance/nonce moved by exactly one tx. **No double-spend, no mint** (conservation verified).

**Impact:** Not a fund-integrity break — the runtime is the authority and re-validates at block time.
The defect is that the mempool advertises txs it cannot honor: silent drops (only a `WARN` log, no
receipt), wasted block-production cycles, and a misleading "accepted" hash returned to the wallet.

**Remediation:** Track a running `pending_spend` per sender in the mempool and reject at submit when
`balance < pending_spend + value` (mirror the existing pending-nonce logic for balance). Low effort,
contained to `ingest_raw_tx`.

---

### F2 — Unbounded mempool / free zero-value flood (Medium)

**Where:** `crates/rpc/src/lib.rs` — `Inner.mempool: Vec<PendingTx>` has no global or per-sender cap;
gas is not charged (documented deviation), so admission is costless.

**Repro (PoC):** a throwaway key with **zero balance**, nonce 0, value 0 was accepted:
```
throwaway sender: 0x267228fC1E0CdD70e5907fDd47451F0bdAa6186C  (zero balance)
eth_sendRawTransaction -> 0x56d39472...  (accepted)
```
With unlimited fresh keys, an attacker pushes unbounded valid zero-value txs at no cost. Gap-nonce
flooding from a single sender is already blocked (`nonce too high` rejected), which bounds the
single-account vector — but the cross-account vector is open.

**Impact:** Memory growth and per-tick block-production work scale with attacker volume. The
per-tick `mem::take` drains the queue each block, capping steady-state accumulation, but a burst
between ticks is unbounded. Local single-node devnet → Medium.

**Remediation:** (a) cap total mempool length and per-sender pending count; reject with a
`-32005`-style "mempool full"/"too many pending" once exceeded. (b) Before any shared deployment,
charge nominal gas or add a minimal per-IP rate limit so admission isn't free.

---

### F3 — RPC body cap / rate limiting (Low)

jsonrpsee's defaults apply (10 MB max body — verified: a ~15 MB request got HTTP 413 `-32007`
"Request is too big"; ~100 max connections). 10 MB is generous for a surface whose only large input
is a single signed tx (well under 1 KB). No per-IP request-rate limit.

**Remediation:** call `Server::builder().max_request_body_size(128 * 1024)` (or similar) in `serve`,
and add rate limiting at a proxy if the devnet is ever exposed beyond localhost.

---

### F4 — `eth_getTransactionCount` ignores block tag (Info)

Returns the latest nonce regardless of the `block` param. Harmless for M1 wallets; note it as an I3
deviation if not already.

---

## Pentest transcript (summary)

Node booted on `127.0.0.1:38545`, chainId `0x5542`, 2 s block tick, dev account streaming
(`eth_getBalance` ≈ 1 UBI/hr confirmed). All attacks below were run against the live node; **no
panic, abort, or crash occurred** (log scanned clean) and the node was killed cleanly at the end.

| # | Attack | Input | Result | Pass? |
|---|--------|-------|--------|-------|
| 1 | Wrong-chain (mainnet) signed tx | EIP-155 tx for chainId 1 | `-32602 wrong chainId: tx is for 1, devnet is 21826` | ✅ rejected |
| 2 | Malformed RLP | `0xdeadbeef`, `0xc0ffee`, `0x`, odd-length `0xabc` | `rlp decode failed` / `bad raw tx hex` | ✅ rejected |
| 3 | Contract creation (`to == None`) | legacy `--create` tx | `contract creation not supported on M1` | ✅ rejected |
| 4 | Non-empty calldata | transfer w/ `0xdeadbeef` input | `calldata not supported on M1` | ✅ rejected |
| 5 | Insufficient balance | send 1000 UBI from ~0.003 UBI acct | `insufficient balance: have …, need …` | ✅ rejected |
| 6 | Value > u128 | value = 2^130 | `value exceeds u128 base-unit range` | ✅ rejected |
| 7 | Replay / duplicate-nonce | resubmit nonce-0 bytes; diff tx same nonce; replay after mine | `nonce too low: expected 1, got 0` (all 3) | ✅ rejected |
| 8 | **Mempool overdraft** | 5× full-balance txs, sequential nonces | all 5 admitted; only 1 mined, 4 dropped at block time; **no double-spend** | ⚠️ F1 (integrity held) |
| 9 | Large / garbage body | 1 MB junk; ~15 MB body; bad JSON; unknown method | RLP error; HTTP 413 `-32007`; `-32700 Parse error`; `-32601` | ✅ handled |
| 10 | Gap-nonce flood (1 sender) | nonce +1000 | `nonce too high` | ✅ rejected |
| 11 | **Free zero-value flood** | fresh zero-balance key, value 0 | **accepted** | ⚠️ F2 |

**Integrity result:** after attack 8, conservation verified — recipient held exactly one transfer's
value (24.4e15 base units), dev balance/nonce moved by exactly one tx; the four over-spend txs were
dropped by the runtime at block time with `WARN dropping tx`. EIP-155 binding, nonce/replay
protection, and balance invariant I2 all held.

## Recommendation
Mark M1-T9 **PASS**. File F1 (mempool balance over-admission) and F2 (mempool cap / costless flood)
as Medium follow-ups to land before any multi-node or non-localhost deployment; F3/F4 are Low/Info.
No product code was modified during this review.
