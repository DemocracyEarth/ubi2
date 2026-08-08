# ADR-0008 — The predicate layer: prove a boolean about a verified human, reveal only the boolean (v1 issuer-attested, with a holder-ZK seam)

- **Status:** accepted (Phase 3, v1)
- **Date:** 2026-08-08
- **Deciders:** architect (this ADR) — to be ratified by protocol-engineer, security-engineer (the issuer
  trust root + anti-replay are security-gate items) at the Phase 3 gates.
- **Supersedes / amends:** nothing. It is **purely additive** to the base Proof-of-Humanity SBT
  ([`ProofOfHumanity.sol`](../../../contracts/src/ProofOfHumanity.sol), spec
  [`03-proof-of-humanity.md`](../03-proof-of-humanity.md)) and the Self/ZK-passport mint path
  ([ADR-0005](0005-zk-passport-poh.md)). It changes no state transition, the mint/refresh path, the
  nullifier, or UBI eligibility. It builds a **read-side** predicate proof on top of the credential the SBT
  already represents.

The credential schema, the two EIP-712 domains, the `PredicateAttestation` typehash, and the anti-replay
key are costly to reverse — once a consumer verifies against them they interoperate forever — so they are
pinned here.

---

## Context

The base SBT already draws the right privacy line: it stores **only** a unique-human nullifier + a coarse
validity epoch, and states that "predicates over identity (age / nationality / sanctions) are proven
off-chain on demand, never stored on-chain" (`HumanityVoucher` / `ProofOfHumanity` NatSpec). What was
missing is the *mechanism* for that on-demand proof — a way for a verified human to convince a **consumer**
(a contract or an app) of a single **yes/no fact** about themselves while:

1. revealing **only the boolean** — no age, no nationality code, no sanctions detail ever reaches the
   consumer, calldata, logs, or storage;
2. staying **unlinkable across consumers** — two consumers cannot collude to correlate the same human;
3. resisting **replay** — a proof shown to one consumer/context cannot be reused elsewhere.

This is the substrate for sybil-resistant, privacy-preserving actions: "only humans over 18 may vote on
this proposal", "only ARG nationals may claim this grant", "only sanctions-clear humans may receive this
stream" — each gate learning nothing but the boolean it asked about.

Three constraints frame the design (all inherited):

- **No PII on-chain, ever** (I6 / base-SBT invariant). There is no field to hold an attribute value; a
  predicate result is a `bool`, and only the `bool` crosses the trust boundary.
- **Mirror the existing trust seam.** Minting pairs a *trusted* `mintWithVoucher` (issuer signs an EIP-712
  voucher) with an *unimplemented* `IHumanityProofVerifier` seam for the future on-chain-ZK path. The
  predicate layer mirrors this exactly: a *trusted* issuer-attested v1 with an unimplemented
  `IPredicateProver` seam for the trustless holder-ZK v2.
- **The deterministic runtime stays dependency-free.** `crates/runtime` has no secp256k1/`k256` and no
  ecrecover; a native runtime twin of the verifier is therefore out of Phase-3 scope (see Decision 6).

---

## Decision 1 — Two credentials with a strict privacy boundary between them

The model has exactly two signed objects. The boundary between them is the whole privacy story.

**`HumanCredential` — the held credential (TypeScript-only, never Solidity).** At Self verification the
issuer additionally signs a credential the holder keeps **privately, off-chain** (localStorage in the demo;
a wallet keystore later). It is the *only* object that carries attribute values, and it never leaves the
holder except back to the issuer. Portable EIP-712 domain **`{name:"ProofOfHumanityCredential",
version:"1"}`** — deliberately **no `chainId` / `verifyingContract`**, so one credential is reusable on any
chain and against any consumer.

```
HumanCredential(uint256 nullifier,uint8 ageFlags,bytes3 nationality,bool ofacClear,uint32 epoch)
```

- `ageFlags` — a bitfield of pre-computed age thresholds (e.g. bit0 = `age>=18`, bit1 = `age>=21`); it
  encodes *which thresholds pass*, never the birth date.
- `nationality` — the ISO-3166-1 alpha-3 code as `bytes3` (decoded via the kept
  [`Countries.sol`](../../../contracts/src/Countries.sol) / `self_attributes.rs` / `poh_countries.rs`).
- `ofacClear` — the sanctions boolean.
- `epoch` — matches the SBT's coarse validity epoch (`block.timestamp / EPOCH`, `EPOCH = 90 days`).

**`PredicateAttestation` — the presentation (crosses into Solidity).** For each predicate request the issuer
signs a fresh attestation bound to **one consumer + one context + one presenter**. Consumer-bound EIP-712
domain **`{name:"ProofOfHumanityPredicate", version:"1", chainId, verifyingContract: <PredicateVerifier>}`**.
The typehash is **byte-identical in Solidity and TS** (a single divergent byte breaks every verification):

```
PredicateAttestation(address consumer,bytes32 context,bytes32 predicate,bool result,address subject,uint32 epoch,uint256 nonce)
```

| field       | meaning / role |
|-------------|----------------|
| `consumer`  | the verifying contract/app — **binds the proof to one consumer** (the unlinkability lever, Decision 3). |
| `context`   | consumer-defined scope (e.g. a proposal id). |
| `predicate` | `keccak256(<canonical descriptor>)` — the question being answered (grammar below). |
| `result`    | the boolean the issuer computed from the `HumanCredential` — **the only fact revealed**. |
| `subject`   | the presenting human's address — **binds the proof to the presenter** (anti-lend / anti-front-run). |
| `epoch`     | must be current-ish; the verifier checks freshness against its own `currentEpoch()`. |
| `nonce`     | anti-replay entropy (Decision 4). |

**Predicate descriptor grammar** (the pre-image the issuer and consumer both hash; document-and-freeze):

```
descriptor := "age>=" INT              // e.g. "age>=18", "age>=21"   → read from ageFlags
            | "nationality=" ALPHA3     // e.g. "nationality=ARG"      → read from nationality
            | "sanctions-clear"         //                            → read from ofacClear
```

`predicate = keccak256(utf8(descriptor))`. New descriptors are additive; a consumer pins the exact hash(es)
it accepts, so it can never be tricked into accepting a different question.

**Rationale.** Splitting a rich, private, portable *held* credential from a minimal, per-request,
consumer-bound *presentation* is what lets the presentation carry **only a boolean** while the issuer still
has enough to compute it. The held credential never touches a chain; the presentation never carries an
attribute value.

**Rejected.** (a) Putting attributes in the on-chain object — breaks I6 and the base-SBT invariant.
(b) A single portable presentation reusable across consumers — would make every consumer a linkage oracle
(Decision 3). (c) A `chainId`/`verifyingContract` in the *credential* domain — would needlessly pin the
portable, chain-agnostic held credential to one deployment.

---

## Decision 2 — v1 is **issuer-attested** (the issuer is the prover), with an unimplemented `IPredicateProver` seam that is the trustless v2

**v1 (this ADR).** The consumer's request flows to the issuer backend (`/api/predicate`): the issuer
re-verifies the holder's `HumanCredential` signature, **computes `result` itself** from the credential's
attributes via the descriptor grammar, and returns a signed `PredicateAttestation`. `PredicateVerifier.sol`
then does nothing but **recover the issuer address from the EIP-712 digest and require it equals the pinned
`issuer`** (plus the binding/freshness/replay checks). The issuer is the same trusted party that already
signs mint vouchers — no new trust root is introduced.

**Trust cost, stated plainly (security-gate item).** In v1 the issuer *sees the attributes* (it holds the
credential to re-verify it) and is *trusted to compute the boolean honestly*. This is the identical trust
posture as `mintWithVoucher` today, and it is the seam's whole point to remove later.

**v2 (the goal, seam only).** `IPredicateProver` is declared and **left unimplemented**, exactly as
[`IHumanityProofVerifier`](../../../contracts/src/ProofOfHumanity.sol) is for the trustless mint path. In
v2 the *holder's own device* produces a zero-knowledge proof that "my credential's attributes satisfy
`predicate`" and the verifier calls `IPredicateProver.verifyPredicate(proof, publicSignals) → (bool result,
address subject, …)` **instead of** recovering an issuer signature. The issuer never sees the attributes and
is not trusted to compute the boolean — the holder proves it. Because the verifier already returns `result`
from behind a seam, this is an **additive, non-breaking** swap: `consume`/`check`, the consumers, and the
anti-replay logic are untouched.

**Rationale.** Shipping the trusted path first (with the boundary, the schema, and the typehash all pinned)
delivers the end-to-end privacy story now, while the seam guarantees the trust-minimizing upgrade is a
drop-in rather than a rewrite — the same staged strategy ADR-0005 uses for mint.

---

## Decision 3 — Unlinkability by per-consumer binding now; per-context pseudonyms noted for v2

Because `consumer` is inside the signed struct **and** the verifier requires `att.consumer == msg.sender`,
an attestation minted for consumer A is cryptographically useless at consumer B. Two colluding consumers
holding the attestations they each received cannot correlate them into "the same human": the attestations
differ, and the only cross-consumer identifier — `subject` — is the human's own address, which the human
controls and can vary. Nothing an attestation reveals (a bare `result`) clusters humans by attribute.

**v2 note (per-context pseudonyms).** The residual linkage is `subject` reuse: a human who presents from the
same address to many consumers is linkable by that address, not by the predicate layer. The holder-ZK v2
closes this by emitting a **per-context pseudonym** (a nullifier-derived, one-way `H(nullifier ‖ context)`)
as the subject binding instead of a reused EOA address — the standard PoH per-context nullifier
construction, and the reason the seam returns `subject` rather than assuming an address. Out of v1 scope;
recorded so v1 does not bake in an address-only assumption.

**Rejected.** A single consumer-agnostic proof (max convenience) — turns every verifier into a linkage
oracle, defeating the core goal.

---

## Decision 4 — Anti-replay: a per-(subject, consumer, context, nonce) key, with a stateful `consume` and a stateless `check`

`PredicateVerifier` exposes two entrypoints:

- **`consume(att, sig, presenter) → bool`** — the **stateful gate**. Recovers the issuer and requires
  `== issuer`; requires `att.consumer == msg.sender`, `att.subject == presenter`, and `att.epoch` fresh
  (`currentEpoch() <= att.epoch + VALIDITY_EPOCHS`, mirroring the SBT's `EPOCH = 90 days`,
  `VALIDITY_EPOCHS = 4`); then computes
  `key = keccak256(att.subject, att.consumer, att.context, att.nonce)` and **reverts if `key` was already
  used, else marks it used** before returning `att.result`. One attestation is spendable once per
  (subject, consumer, context, nonce).
- **`check(att, sig, presenter, consumer) → bool` (view)** — the **stateless** twin: the identical
  recover/bind/freshness checks **without** the replay-state write, for read-only gates and off-chain
  verification that must not mutate state.

Scoping the key by `consumer` and `context` (not a global nonce) means a human can legitimately answer the
same predicate for *different* proposals/apps; only exact reuse within one scope is blocked. The freshness
window binds the attestation to a recent epoch so a long-past attestation cannot be resurrected.

**Rejected.** (a) A global monotone nonce per subject — would serialize a human across unrelated consumers.
(b) Relying on `context` alone without a `nonce` — would forbid two legitimate presentations in the same
context; the `nonce` restores that while keeping each single presentation single-use.

---

## Decision 5 — On-chain vs off-chain consumers; the `SybilResistantVote` demo proves the whole thesis

**On-chain consumers** call `consume` (they need the one-shot replay guarantee committed to state).
**Off-chain / stateless consumers** call `check` (a pure verification; they enforce their own
idempotency). The same attestation format serves both.

The demo consumer **`SybilResistantVote.sol`** composes the base SBT gate with the predicate gate to show
the end-to-end property:

- `poh.ownerOf(tokenId) == msg.sender` && `poh.isValid(tokenId)` — a **unique, currently-valid human**
  (reusing the base SBT's read surface unchanged).
- `!voted[tokenId]` — **one human, one vote**.
- `pv.consume(att, sig, msg.sender) == true` with `att.predicate == requiredPredicate` &&
  `att.context == context` — the human **satisfies the gate predicate** (e.g. `age>=18`) for **this**
  proposal.

The vote records support/against and the token id. **No age, nationality, or sanctions value appears in
calldata, logs, or storage** — only the boolean gate result and the anonymous SBT id. This is the concrete
demonstration that a privacy-preserving, sybil-resistant action is possible on the base SBT.

---

## Decision 6 — The ubi2-native runtime twin is deferred to **Phase 3b** (needs secp256k1 recovery in the deterministic runtime)

`PredicateVerifier` is a Solidity contract on the EVM-compatible chain (and, by identical bytecode, any EVM
chain). ubi2 also has a **deterministic native runtime** (`crates/runtime`) that answers system-address
"precompile" ops (StreamHub, the `HumanityHub` PoH seam). A **native twin** — verifying a
`PredicateAttestation` *inside* the deterministic runtime so a native governance op can be predicate-gated
without a full EVM — is desirable but **out of Phase-3 scope**, for one concrete reason:

- Verifying an attestation requires **ecrecover of the EIP-712 digest** to recover the issuer. `k256`
  (secp256k1 ECDSA) is present in `crates/node`, `crates/network`, and the browser `crates/exec` kernel,
  but **`crates/runtime` is deliberately dependency-free and the deterministic kernel never calls it**
  (the same rule that keeps the consensus path free of async/network/float/crypto deps — see ADR-0005
  Decision 2). A native twin needs a **deterministic, canonical-encoding secp256k1 recovery** available
  *inside* `runtime` first.

**Phase 3b** therefore covers: (1) landing deterministic secp256k1 recovery in the runtime (behind a trait,
the ADR-0005 pattern), (2) a native `PredicateVerifier` twin as a `HumanityHub`-style op with the
byte-identical typehash and anti-replay key, so the same attestation verifies identically on the EVM and in
the native runtime. Until then, predicate gating is an **EVM-contract feature**; the native chain consumes
it via `eth_call`/contract execution, not via a native precompile.

**Rejected.** Adding a crypto dependency to `runtime` to ship a native twin now would violate the
dependency-free consensus rule for a feature the EVM path already covers — a bad trade this milestone.

---

## Status of invariants

- **I1 (deterministic consensus over non-deterministic AI):** unaffected — the predicate layer adds no AI
  and no consensus primitive; v1 verification is a pure EIP-712 signature check in a contract. The deferred
  native twin (Decision 6) will ride re-execution consensus exactly as ADR-0005 Decision 5 does.
- **I3 (EVM compatibility):** preserved. `consume`/`check`/`vote` are ordinary contract calls; MetaMask
  signs the txs unchanged; no `eth_*` semantics change.
- **I6 (least authority / privacy):** **central and strengthened.** Only a boolean crosses the on-chain
  boundary; attribute values live solely in the holder's private `HumanCredential`; per-consumer binding
  gives cross-consumer unlinkability. The known residual (v1 trusts the issuer to compute the boolean;
  `subject` address reuse is linkable) is exactly what the `IPredicateProver` + per-context-pseudonym v2
  removes.

## Open follow-ups created / closed by this ADR

- **Closes (v1):** an end-to-end, boolean-only, replay-safe, per-consumer-unlinkable predicate gate on the
  base SBT, with the schema + typehash + anti-replay key pinned.
- **Defers to v2 (trustless):** implement `IPredicateProver` (holder-side ZK over the held credential);
  per-context pseudonyms replacing the reused-address `subject` binding (Decision 3).
- **Defers to Phase 3b:** deterministic secp256k1 recovery in `crates/runtime` + the native
  `PredicateVerifier` twin (Decision 6).
- **Security-gate items:** the issuer is trusted to compute `result` honestly and sees attributes in v1
  (Decision 2); the anti-replay key + freshness window (Decision 4) are the replay defenses to review.
