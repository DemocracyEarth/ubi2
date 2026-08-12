# 09 — Predicate v1.5: trustless on-demand age (+ nationality / OFAC) proofs via Self

- **Status:** deferred as a standalone product release by [ADR-0010](adr/0010-direct-v2-portable-zk-credential.md);
  its Self/Groth16 components remain reusable v2 issuance/verifier infrastructure
- **Owner:** architect → protocol-engineer (contract), interface-engineer (SDK/app), security-engineer (gate)
- **Depends on:** [ADR-0008](adr/0008-predicate-layer.md) (predicate v1), [ADR-0009](adr/0009-predicate-v2-and-final-onchain-surface.md)
  (the fixed `IPredicateProver` seam), [`06-zk-passport-poh.md`](06-zk-passport-poh.md) +
  [`06b-zkpassport-selfxyz-integration.md`](06b-zkpassport-selfxyz-integration.md) (Self proof layout),
  `crates/zkpoh` (the pinned Self verifying key + captured proofs).

## Goal

> **Sequencing update (2026-08-11):** the project is building the reusable v2 credential next. This spec is
> retained as a bounded fallback and source of shared Self verifier work, not as a required v1.5 launch.

Deliver the **first fully-trustless predicate prover** — proving `age>=N` (then `nationality=A3`,
`sanctions-clear`) with **no issuer signature over the boolean** — by reusing **Self's existing Groth16
circuit** and plugging it into the **already-final** `PredicateVerifier` via `IPredicateProver`. A consumer
verifies a proof, not a company's signature; the trust root becomes the passport-issuing state's PKI + the
Self identity registry — exactly the root that already backs the humanity mint.

This is deliberately the **cheapest real trustless win**: it introduces **no new circuit** (Self already
proves `minimumAge`), and it shares its on-chain verifier with the trustless mint path
(`ProofOfHumanity.mintWithProof` / `IHumanityProofVerifier`, still unbuilt). It is *not* the reusable
anonymous-credential system — that is v2.

## Non-goals

- Reusable/offline proofs (re-scan per proof or per session is accepted here; v2 removes it).
- A new attribute circuit (we only consume what Self already discloses: `minimumAge`, `nationality`, `ofac`).
- Any change to the base SBT or the v1 issuer path (both keep working unchanged).

## Trust model

| | v1 (issuer) | **v1.5 (this spec)** |
|---|---|---|
| Who asserts the boolean | issuer's EIP-712 signature | a Groth16 proof over the passport |
| Trust root | trust the issuer | passport-issuer PKI + Self registry (same as the mint) |
| Forgeable "yes" | yes if issuer dishonest / key leaks | no — `age<N` cannot produce a valid `minimumAge=N` proof |
| Issuer online per proof | yes | **no** (issuer plays no part in proving) |

## Architecture

Three additive pieces behind the fixed seam; nothing else moves.

```
 user's phone (Self app)                          consumer contract / app
 ┌───────────────────────┐   proof+signals   ┌──────────────────────────────┐
 │ fresh Self proof with │ ───────────────▶  │ PredicateVerifier            │
 │ minimumAge:N, bound   │                   │  .consumeWithProof(proof,     │
 │ to (consumer,context) │                   │      signals, context)        │
 └───────────────────────┘                   │   → prover.verifyPredicate()  │
                                              │   → freshness + anti-replay + │
        SelfPredicateProver (IPredicateProver)│     consumer/subject binding  │
        verifies Groth16 vs pinned Self vkey ◀┘   → returns bool             │
```

### 1. Client flow (SDK/app) — `buildSelfPredicateApp`

A second Self request distinct from the mint (`apps/proofofhumanity/app/self-client.ts` currently discloses
only `{ ofac }`). For an age gate:

- `disclosures: { minimumAge: N }` (Self proves `olderThan >= N` in ZK; the birthdate never leaves the phone).
- **Bind the proof to the presentation**: encode `(consumer, context)` into the Self request
  (`scope` + `userDefinedData`/`userContextData`) so the resulting proof is valid **only** for this consumer
  + context. This is what gives per-consumer **unlinkability** (different context ⇒ different pseudonym) and
  **anti-replay** (a proof for consumer A can't be presented to B).
- Package the returned `proof` + `publicSignals` for `consumeWithProof`.

### 2. `SelfPredicateProver.sol` (implements `IPredicateProver`)

Stateless. `verifyPredicate(bytes proof, uint256[] publicSignals, bytes context)`:

1. **Verify the Groth16 proof** against the pinned Self verifying key. Reuse the **same** EVM Groth16
   verifier the trustless mint needs (`IHumanityProofVerifier` seam) — build it once, share it. The vkey is
   `crates/zkpoh/fixtures/self_prod_vkey.json`; the public-signal layout is the 21-signal Self layout in
   spec 06/06b (`SELF_IDX_SCOPE`, `SELF_IDX_USER_IDENTIFIER`, the disclosed `olderThan`/nationality/OFAC
   fields; date → epoch).
2. **Re-bind every public signal** (never trust unbound inputs — mirror the mint's signal re-binding, ADR-0005):
   - `scope == expected proofofhumanity scope`;
   - the disclosed `olderThan` signal `>= N` (⇒ `result = true`; a valid proof for `minimumAge=N` only
     exists when the human is at least `N`);
   - `subject` = the address bound by `userContextData` (same `hash160(userContextData)` binding the mint
     uses to tie the proof to the presenter — see spec 06/ADR-0005);
   - `epoch` = `date-in-proof / EPOCH` (coarse, for freshness);
   - `context` matches the consumer-supplied presentation context.
3. Return `(subject, keccak256("age>=N"), true, epoch)`.

For `nationality=A3` → check the disclosed nationality signal equals the requested code; for
`sanctions-clear` → check the OFAC signal. Same shape.

### 3. `PredicateVerifier.consumeWithProof` (from ADR-0009)

Applies the **shared** checks so the prover stays minimal: `consumer == msg.sender`, `subject == presenter`,
`_isFresh(epoch)` (within `VALIDITY_EPOCHS` — mirrors the SBT's ~1-year window), and anti-replay on
`consumed[keccak(subject, consumer, context)]`. Returns the boolean.

## Where verification runs

- **EVM (Base/Celo/Ethereum):** `SelfPredicateProver` verifies the Groth16 proof **on-chain**. A pairing
  check is ~200–300k+ gas — fine for high-value gates, and cheap on the L2s (deploy there first). This is the
  same verifier the trustless mint needs, so the cost is shared, not duplicated.
- **ubi2 native:** the runtime already verifies Self Groth16 proofs natively (`crates/zkpoh`); the predicate
  twin reuses that path (Phase 3b — needs the pairing/secp ops in the deterministic runtime, mirroring the
  native mint verifier). Cheaper than EVM.
- **Off-chain-only gates** (a DAO API, not a contract) may verify with the client-side verifier + the pinned
  vkey — still trustless (the verifier code + vkey are public), no issuer.

## UX trade-off

The human re-scans their passport (or reuses a short-lived Self session) per proof. Acceptable for
high-assurance, occasional gates (voting, jurisdiction gating). The **reusable** experience — one credential,
unlimited offline unlinkable proofs — is exactly what **v2 (anonymous credential)** adds; v1.5 is the
trust-model upgrade without the credential-system build.

## Dependencies to build

1. **EVM Self Groth16 verifier** (`IHumanityProofVerifier` concrete) — the one genuinely new on-chain piece;
   generated from `self_prod_vkey.json`. Shared with the trustless mint path. This is the bulk of v1.5.
2. `SelfPredicateProver.sol` (thin: verify + re-bind signals + map to the predicate).
3. `PredicateVerifier` seam from ADR-0009 (`prover`, `setPredicateProver`, `consumeWithProof`, `checkProof`).
4. SDK: `buildSelfPredicateApp` + packaging helpers; a **"prove 18+ trustlessly"** demo augmenting the v1
   issuer demo so the difference is visible.

## Definition of done

- `SelfPredicateProver.sol` + tests: verifies a **captured real** Self `minimumAge` proof
  (`crates/zkpoh/fixtures`); an `age<N` proof cannot validate; wrong `scope`/consumer/context/subject fails;
  stale `epoch` fails; replay reverts; **no attribute value** (exact age, DOB, nationality) appears in
  calldata / logs / storage (assert with `vm.record`).
- `PredicateVerifier.consumeWithProof` + tests; `check`↔`consume` parity for the proof path.
- A cross-stack test: the client builds a bound Self predicate request, the on-chain prover accepts it, a
  demo consumer gates on it — revealing only the boolean.
- Gas for `consumeWithProof` measured + recorded; runs on a Base/Celo testnet end-to-end.
- ADR-0009's `IPredicateProver` interface unchanged (this is a pure backend behind it).

## Phasing

- **v1.5a** — `age>=N` on Base + Celo (L2 gas), verified on-chain. Ship the shared Self Groth16 verifier.
- **v1.5b** — `nationality=A3` + `sanctions-clear` (same mechanism, different disclosed signal).
- **v1.5c** — ubi2-native predicate twin (runtime verifier; Phase 3b).

## Open items (resolve before build)

- **Self per-context binding:** confirm Self binds a proof to `(consumer, context)` strongly enough for
  per-consumer unlinkability + on-chain anti-replay (via `scope`/`userDefinedData`/`userContextData`). If
  not, add an app-level pseudonym derivation. This is the one external unknown.
- **On-chain gas** acceptance on Ethereum L1 (vs. L2-only for v1.5).
- **Nullifier ↔ subject:** reuse the mint's `userContextData` → address binding so a predicate proof and the
  SBT refer to the same human without a new linkage.
