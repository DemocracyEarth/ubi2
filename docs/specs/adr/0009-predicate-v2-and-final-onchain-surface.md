# ADR-0009 — A final on-chain predicate surface, with a progressive trust model (issuer → Self-ZK → anonymous credential)

- **Status:** proposed
- **Date:** 2026-08-09
- **Deciders:** architect (this ADR) — to be ratified by protocol-engineer + security-engineer at the
  mainnet-deploy gate (the prover seam + the owner's `setPredicateProver` power are security items).
- **Extends:** [ADR-0008](0008-predicate-layer.md) (predicate layer v1, issuer-attested). Amends **nothing**
  in the base SBT ([`ProofOfHumanity.sol`](../../../contracts/src/ProofOfHumanity.sol)); it pins how the
  predicate **verifier** evolves so the on-chain deployment can be **final now**.
- **Companion spec:** [`09-predicate-v1_5-self-age.md`](../09-predicate-v1_5-self-age.md) (the first ZK prover).

> **Sequencing update (2026-08-11):** [ADR-0010](0010-direct-v2-portable-zk-credential.md) supersedes the
> “Why NOT go straight to full v2” conclusion below. The fixed `IPredicateProver` surface and migration
> analysis in this ADR remain the chosen architecture; v1.5 is now reusable infrastructure rather than the
> next standalone product release.

---

## Context

v1 (ADR-0008) shipped: a verified human proves a yes/no predicate (`age>=18`, `nationality=ARG`,
`sanctions-clear`) to a consumer, revealing **only the boolean**, unlinkable per consumer, nothing stored
on-chain. The *privacy* is real. The *trust* is a signature: the **issuer** re-checks the human's private
off-chain credential and signs the boolean; the consumer trusts that signature.

We are about to deploy the contracts to **Base, Celo, and Ethereum mainnet**. That raised the right
question: *should we deploy now on v1, or wait for the fully-trustless ZK v2 so the on-chain deployment is
**final** and we don't ship contracts we'll have to replace?*

The resolution is a distinction the current code already makes but hasn't been stated as policy — the
on-chain surface splits into **durable** and **replaceable**:

| Surface | Holds | Migration cost | Depends on predicate version? |
|---|---|---|---|
| `ProofOfHumanity` (SBT) | the humans — `nullifier → token`, validity epoch, UBI eligibility | **high** (real user state) | **No** — stores no predicate logic |
| `PredicateVerifier` + provers | only anti-replay nonces (no human state) | **low** (additive, no state to migrate) | **Yes** — the whole predicate *version* lives here |

So "wanting a final deployment" is **not** a reason to delay the launch for the full ZK build. The durable
contract is already version-agnostic and final; the verifier just needs to be deployed in a shape that lets
the *proving backend* be swapped without a redeploy — and its `IPredicateProver` seam already exists for
exactly that.

## Decision

**1. Deploy the base SBT now — it is final and predicate-version-agnostic.** No change. This is the contract
you must never casually redeploy (it holds the humans + gates UBI); it carries no predicate logic, so no
future predicate work touches it.

**2. Before mainnet, make `PredicateVerifier` a permanent host for BOTH the issuer path and any ZK prover.**
Extend it (purely additive to the v1 surface):
- `IPredicateProver public prover;` + `setPredicateProver(IPredicateProver) onlyOwner` (+ event).
- `consumeWithProof(bytes proof, uint256[] publicSignals, bytes context) returns (bool)` and a stateless
  `checkProof(...)` view that:
  1. call `prover.verifyPredicate(proof, publicSignals, context)` → `(subject, predicate, result, epoch)`;
  2. apply the **same shared checks** the issuer path already enforces — `consumer == msg.sender`,
     `subject == presenter`, epoch freshness (`_isFresh`), and **anti-replay** on the `consumed` map with a
     key derived from `(subject, consumer, context)` (the consumer supplies a fresh `context` per
     presentation, e.g. a proposal id + nonce);
  3. return `result`. Revert if `prover` is unset.
- Keep v1 `consume(PredicateAttestation, sig)` untouched.

Result: **one deployed verifier address serves the trusted-issuer path today and every ZK prover later.**
Consumers never change the address they trust; upgrading the trust model is a `setPredicateProver` tx, not a
redeploy or a migration.

**3. Pin `IPredicateProver` as a forever-interface** — it is the read-side analogue of v1's EIP-712 typehash
(costly to change once consumers integrate). It is intentionally proof-system-agnostic:
```solidity
function verifyPredicate(bytes proof, uint256[] publicSignals, bytes context)
    external view returns (address subject, bytes32 predicate, bool result, uint32 epoch);
```
Groth16 fits today; PLONK/STARK/BBS+ presentations are still "opaque bytes + public signals + context", so
the interface survives a backend change. Variable, backend-specific data goes in `publicSignals`/`context`,
never in the signature.

**4. Ship the proving backends as a progression *behind the fixed seam*** — not as contract versions:

| Backend | Trust root | Boolean forgeable? | Issuer online per proof? | Reusable / offline? | Status |
|---|---|---|---|---|---|
| **v1 issuer-attested** | the issuer's signature | yes, if issuer dishonest / key leaks | yes | no | live (ADR-0008) |
| **v1.5 Self on-demand ZK** | passport-issuer PKI + Self registry (same as the humanity mint) | no — false claim can't produce a valid proof | no | no (re-scan per proof/session) | spec 09 |
| **v2 anonymous credential** | issuer at *issuance* only (or passport-native) | no | no | **yes** — unlimited unlinkable local proofs | roadmap |

**5. Consumers opt into which paths they accept.** A consumer can accept the issuer path, the ZK path, or
both against the same verifier address. `SybilResistantVote` (demo) documents both.

## Why NOT go straight to full v2

Going straight to the fully-trustless anonymous-credential v2 before deploying would delay the launch by a
**new circuit + prover + credential format + a security audit** (months + audit spend) — for **zero** added
finality, because:

- The **seam gives finality now**: the durable SBT is final, and the verifier hosts every future backend at
  a fixed address.
- **v1 lets you launch predicate-gated features immediately** and learn which predicates consumers actually
  demand before investing in a general circuit.
- **v1.5 is a genuine trustless win that reuses existing infrastructure** — Self's Groth16 age/nationality/
  OFAC circuit (`crates/zkpoh` already holds the verifying key + captured proofs), and the **same on-chain
  Groth16 verifier the trustless MINT path needs anyway** (`ProofOfHumanity`'s declared-but-unbuilt
  `mintWithProof` / `IHumanityProofVerifier`). It is shared investment, not a throwaway "medium release."

Net: the seam converts every "medium release" from a **contract migration** into an **off-chain/prover
swap**. You get final contracts *and* a progressively hardening trust model.

## Consequences

**Positive**
- On-chain deployment is **final at launch**. Hardening the trust model = deploy a prover + one owner tx.
- No SBT change, no verifier redeploy, no consumer migration, ever, across v1 → v1.5 → v2.
- Anti-replay / freshness / consumer-binding live **once** in the verifier, so provers stay small,
  swappable, and independently auditable.

**Negative / costs**
- Consumers must add a `consumeWithProof` call to accept ZK proofs (additive; the v1 path keeps working).
- `IPredicateProver` must be right the first time — mitigated by its maximal generality (bytes + signals +
  context).
- The owner (a multisig) can set the prover — a governance surface. Mitigation: it is the **same** multisig
  that already rotates the issuer; a malicious/broken prover can only mislead predicate *consumers that
  opted into the ZK path* — it can **never** touch the SBT, the nullifier set, or UBI eligibility.

## Migration

None for the SBT. `PredicateVerifier` gains methods (additive; v1 callers unaffected). Consumers adopt
`consumeWithProof` when they want the ZK path. The `consumed` anti-replay map is per `(subject, consumer,
context)`, so the two paths don't collide.

## Open questions / risks

- **Interface generality** across proof systems — believed adequate; if a backend needs extra public inputs,
  they go in `publicSignals`/`context`. Revisit only if that proves insufficient.
- **On-chain Groth16 gas** for v1.5 (a Self proof is a pairing check, ~200–300k+ gas). Acceptable for
  high-value gates; favor L2s (Base/Celo) first; the ubi2 runtime verifies natively (cheaper).
- **Trusted setup / vkey management** for the Self circuit — already pinned in `crates/zkpoh/fixtures`
  (`self_prod_vkey.json`).
- **ubi2-native predicate twin** — needs pairing/secp in the deterministic runtime (mirrors the native mint
  verifier; Phase 3b). Until then, ubi2 predicates use the same EVM-style verifier semantics.
- **Self per-context binding** — v1.5 depends on Self binding a proof to a presentation context strongly
  enough for per-consumer unlinkability + anti-replay. Confirmed sufficient in spec 09 before build.
