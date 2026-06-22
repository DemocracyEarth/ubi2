# Security gate — M4 prompt contracts (board M4-T8)

**Verdict: PASS** — no open High/Critical on the M4 diff (commit ce1de45).
PoCs: `crates/runtime/tests/sec_m4_poc.rs` (6, all green). *(This report was reconstructed by the
orchestrator from the gate's structured result — the gate's own file write did not land.)*

## Scope & threat model
Pentested the full M4 surface: the escrow / least-authority boundary, the AI interpreter
(prompt-injection), quorum/abort integrity, replay/signature, privacy (I6), and DoS.

## Boundaries verified intact (positive findings)
- **Escrow / least authority (I6):** `apply_effect` validates the **whole** effect (solvency sum across
  Transfer+Refund+OpenStream draws, party-authority on `Refund`, stream-ownership on `StopStream`, stream
  bounds) **before any mutation**, and applies **atomically all-or-nothing** (I4). A fooled interpreter is
  re-validated and bounded to the contract's **own escrow + declared parties** — it cannot reach other
  accounts, over-draw, or leave partial state. Confirmed by live PoCs (a `ClaudeInterpreter` told to drain
  1000 UBI from a 3-UBI escrow → aborts, attacker balance 0).
- **Interpreter prompt-injection:** prompts use role separation, defanged untrusted fences for the contract
  text + trigger, a closed structured-output schema, and fail-closed total decoding. The deterministic
  runtime is the real backstop — a successful jailbreak still cannot produce an over-authority effect.
- **Quorum/abort integrity (I1/I4):** tally is order-independent + deterministic; a split aborts with no
  state change; non-jurors / double-submits / closed-cases are rejected; a re-invocation cannot replay a
  committed effect.
- **Replay/signature:** EIP-155 + nonce protect every write op (deploy/fund/invoke/submitEffect).
- **Privacy (I6):** only commitments (`text_ref`/`trigger_ref`) + addresses/amounts on-chain — no contract
  prose or PII; the EXPL-1 indexer leaks nothing sensitive.

## Findings (all non-blocking; tracked as follow-ups)
| # | Severity | Title |
|---|---|---|
| 1 | **Medium** | **Stranded-funds desync** — a *plain* value transfer (empty calldata) sent directly to a contract's escrow **address** raises the escrow account balance but not the tracked `contract.escrow`, so those funds become permanently unmovable (no effect releases them; `Refund` needs a party and draws cap at `contract.escrow`). Fund-loss-by-**footgun**, NOT theft/over-draw (validation against the lower `contract.escrow` keeps account balance ≥ tracked escrow, so the apply-phase invariant never trips — no consensus halt). Contradicts spec 04 (a direct transfer to the contract id should raise escrow). PoC `direct_transfer_to_escrow_desyncs_accounting`. **Fix before mainnet** — architect-preferred: derive `contract.escrow` from `balance(escrow_addr)` as the single source of truth (also removes lock-step maintenance); alternatives: reject plain transfers into ContractHub escrow space at ingestion, or fold surplus into escrow on invoke. → **FU-9**. |
| 2 | Low | Per-invoke O(N log N) full scan of the exec-case set at block production (`contract_effect_addresses()` clones+sorts the whole map per committed invoke) — amortized-quadratic block cost under sustained invoke load (nonce/gas-gated, can't halt the node); also mis-attributes effect addresses when two invokes for one contract land in a block. Fix: thread the `case_id` `invoke_contract` returns through `PendingKind::InvokeContract`. → **FU-10**. |
| 3 | Info | `msg.value` on non-fund ContractHub txs (deploy/invoke/submitEffect) is silently ignored rather than rejected — benign (no loss) but differs from EVM least-surprise. Consider rejecting value-bearing non-fund txs at ingestion. → **FU-11**. |

(Reliability also noted Info doc cleanups: `fnv1a_256` docstring says "eight lanes" but `BASES` has 4;
`MemState::accounts()`/`streams()` return unsorted collections — not on any consensus path today. → FU-11.)
