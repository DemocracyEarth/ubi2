# 04 — Milestone 4: Natural-language prompt contracts (intent-as-law)

**Status:** spec (architect, cycle 4).
**Goal:** contracts written in **plain language**, executed by AI nodes that parse intent and reach
**consensus on the outcome**. A contract is deployed as natural-language text; when invoked, a **quorum of
interpreter nodes** each maps `(contract text, state snapshot, trigger input)` → a **canonical structured
effect** (a bounded state delta); the effect commits **only if a quorum produces the same canonical
effect**, else it **aborts deterministically**. *Intent-as-law*, not code-as-law.

This **reuses the M3 AI-quorum substrate**: the `Case`/`Juror`/quorum-tally machinery and the
canonical-verdict determinism (invariant I1) generalize from "is this a human?" to "what is this
contract's effect?". The interpreter quorum is the same consensus primitive as the verifier quorum.

## The hard problem (and why this is safe)
Natural language is ambiguous; a blockchain needs deterministic, reproducible execution. We make it safe by:
1. Committing the **effect** (a typed state delta), never the prose.
2. Requiring an **independent quorum** of interpreters to produce the *same* canonical effect (≥⌈2N/3⌉).
3. **Aborting deterministically** on any disagreement/ambiguity — no partial state, ever (I4 fail-closed).
4. Bounding every effect by **least authority** (I6): a contract can only move its **own escrowed funds**
   and do what its parties authorized — it can never reach into accounts that didn't grant it authority.

## Canonical effect language (D1 — bounded, typed, deterministic)
The interpreter does NOT emit prose or code; it emits an ordered list of typed ops the runtime applies
atomically (all-or-abort). All amounts are integer base units (I2). M4 v1 set:
```
Effect = [Op]                                   // ordered; applied atomically; empty = no-op
Op =
  | Transfer   { to: Address, amount: u128 }    // from the contract's escrow to an account
  | Refund     { party: Address, amount: u128 } // return escrow to a named party
  | OpenStream { to: Address, rate: u128, deposit: u128 }   // from escrow (reuses M2)
  | StopStream { id: StreamId }                 // a stream the contract owns
  | SetVar     { key: bytes32, value: bytes32 } // contract-local kv (stateful contracts)
  | Abort      { reason_hash: bytes32 }         // explicit deterministic abort (no state change)
CanonicalEffect { ops: Effect, effect_hash: Hash }   // hash over the canonical-encoded ops
```
Quorum equality compares the **canonical-encoded ops** (effect_hash); reasons/explanations are off-chain.
The op set is intentionally small and extends by ADR — no loops, no Turing-completeness, no cross-contract
calls in M4 (deferred). Expressiveness comes from the NL + the interpreter, not a VM.

## Authority & escrow (D4 — least authority)
A `PromptContract` holds an **escrow account** (its own address-like id). Parties **fund** the escrow
(a normal transfer / stream into the contract id) and that is the **only** value the contract can move.
Validation at apply-time (deterministic, in the runtime — not the LLM): every `Transfer`/`Refund`/
`OpenStream` draws from escrow and is rejected (→ whole-effect Abort) if it exceeds the escrow balance;
`Refund` may only target a declared party. So a contract is solvent-by-construction like M2 streams, and a
malicious/ambiguous interpretation can at worst drain only what was escrowed into that contract.

## Data model (`crates/runtime`)
```
ContractId = u64
PromptContract {
  id, escrow: u128, parties: [Address],
  text_ref: Hash,            // commitment to the NL contract text (text stored off-chain / in calldata)
  vars: Map<bytes32,bytes32>,// contract-local state (SetVar)
  status: Active | Terminated,
}
ExecCase {                   // one invocation under interpretation (parallels M3 Case)
  id, contract: ContractId, trigger_ref: Hash, invoker: Address,
  jury: [Address],           // interpreter quorum, selected like M3 jurors
  effects: Map<juror, CanonicalEffect>,
  status: Open | Committed(CanonicalEffect) | Aborted,
}
```
Reuse: generalize M3's juror registry + selection + tally. Recommended implementation — a generic
`quorum_tally<T: QuorumEq>` over submitted items (M3 `CanonicalVerdict`, M4 `CanonicalEffect`) so both
milestones share one audited consensus path; the architect signs off on the refactor vs. a parallel copy.

## Execution lifecycle (deterministic state machine)
```
deployContract(text_ref, parties)             → Active contract (escrow 0)
fund: a normal transfer / openStream to the contract id raises escrow
invokeContract(id, trigger_ref)               → opens an ExecCase, selects an interpreter quorum
each interpreter (off-chain) computes CanonicalEffect = interpret(text, state_snapshot, trigger) and
  submits it via submitEffect(caseId, effect)
tally: ≥QUORUM identical effect_hash → validate ops vs escrow/authority →
   valid   → apply atomically (Committed)        // intent executed
   invalid → Aborted (no state change)            // fail-closed
   no quorum / split → Aborted deterministically  // no partial state
```
The **state snapshot** the interpreters see is content-addressed (contract text + the specific state the
contract may read + the trigger), so honest interpreters see identical inputs and converge. Pinned model,
temperature 0, canonical effect schema (I1/I5 — fixture-testable offline with a `MockInterpreter`).

## The interpreter oracle (`crates/oracle`, reuses the M3 pattern)
```
trait ContractInterpreter: Send + Sync {
    fn interpret(&self, contract_text: &[u8], state: &ContractStateView, trigger: &[u8]) -> CanonicalEffect;
}
```
`ClaudeInterpreter` (Claude-backed, structured output, temp 0, **prompt-injection-resistant**: the contract
text AND the trigger input are untrusted data — fence them; the model may only emit the canonical effect
schema, never free actions) + a deterministic `MockInterpreter` for tests. The node runs `MockInterpreter`
on the devnet (deterministic); the real interpreter runs in the off-chain juror/interpreter daemon (FU-7).

## RPC / interfaces
- Write (EIP-155 txs to a `ContractHub` system address `0x0000000000000000000000000000000000005043`):
  `deployContract(bytes32 textRef, address[] parties)`, `fundContract(uint256 id)` (or a normal transfer to
  the contract id), `invokeContract(uint256 id, bytes32 triggerRef)`, `submitEffect(uint256 caseId, bytes ops)`.
- Read (`ubi_*`): `ubi_getContract(id)`, `ubi_getExecCase(id)`, `ubi_getContractsOf(address)`.
- Wallet: **write a contract in plain language**, deploy, fund, invoke, and watch the committed effect.

## Invariants
- **I1** deterministic interpreter quorum (commit the canonical effect only on quorum; abort on disagreement).
- **I2** effects are integer ops; balances/streams stay pure functions of `(state, now)`.
- **I4** fail-closed: ambiguity / split / invalid-effect ⇒ deterministic Abort, no partial state.
- **I6** least authority: a contract moves only its own escrow; the contract text + trigger are untrusted
  input to the interpreter; no PII; effect validation is in the deterministic runtime, not the LLM.

## Acceptance criteria (map 1:1 to tests; AI parts use `MockInterpreter`)
1. Deploy a NL contract, fund its escrow, invoke it; a quorum-agreed effect transfers from escrow to a
   payee exactly as the plain-language intent specifies; balances reconcile to the base unit.
2. **Solvency/authority:** an effect that would move more than the escrow, or touch a non-party/non-escrow
   account, is rejected → the whole invocation **Aborts** with no state change.
3. **Quorum determinism (I1):** identical `(text, state, trigger)` + `MockInterpreter` ⇒ identical
   `CanonicalEffect` across interpreters; ≥QUORUM commits; a split **Aborts deterministically** — reproducible
   across two nodes.
4. **Injection resistance:** a contract/trigger crafted to make the interpreter emit an out-of-scope or
   over-authority effect fails closed (the runtime rejects the effect and/or the model is fenced to the schema).
5. A streaming prompt contract (e.g. "stream 1 UBI/hr to Bob for 10 hours from escrow") opens an M2 stream
   from escrow; stop/refund returns unused escrow to the parties; totals conserved.
6. Wallet: author → deploy → fund → invoke a plain-language contract against the devnet and see the effect.

## App consolidation (observation, folded into M4's interface phase)
The localhost app (`apps/wallet`) becomes the **UBI app** — the single on-ramp: wallet + **full block
explorer** (browse all blocks/txs/accounts, search by hash/address, per-account history) + the **social /
proof-of-humanity** hub (your status, your vouches in/out, vouch for / challenge others, pending cases,
jurors) + **contracts** (author/deploy/invoke). The proper explorer needs a node-side **address index**
(EXPL-1: today txs are indexed by hash + block, not by account) — a lightweight indexer behind the RPC
(`ubi_getAddressActivity`, `ubi_getAccount`), then the explorer + social UI on top.

## Scope cuts (deferred, recorded)
Time/event triggers + external-data oracles; cross-contract calls; loops/Turing-completeness; on-chain
storage of full contract text (M4 stores a commitment + text in calldata/off-chain); the real interpreter on
the consensus path (FU-7 juror daemon). Multi-node juror staking is M5 (FU-8).

## Open questions for M4-T1 finalization
- Generic `quorum_tally` refactor (share with M3) vs. a parallel `ExecCase` tally.
- Where contract text lives (calldata blob vs. off-chain by `text_ref`) and how interpreters fetch it deterministically.
- `ContractHub` escrow as a distinct address space vs. reusing the account model with a contract-id→address map.
