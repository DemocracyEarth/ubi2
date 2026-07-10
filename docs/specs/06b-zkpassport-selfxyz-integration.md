# 06b — ZK-Passport via Self (self.xyz): REAL passport-verified human nodes (M6 Stage C)

- **Milestone:** M6 **Stage C** (the app / real-proof flow). **Status:** specified (docs-only; implementation
  after this spec is decomposed).
- **Owner:** architect. **Amends:** [`06-zk-passport-poh.md`](06-zk-passport-poh.md) §3/§4/§7 and
  [`adr/0005-zk-passport-poh.md`](adr/0005-zk-passport-poh.md) Decisions 1, 3, 4 (see §11 — the changes are
  costly-to-reverse and are recorded honestly; ratification is deferred to **ADR-0008**, open item O-C6).
- **Reuses:** M6 Stage A/B (`crates/zkpoh` `Groth16Verifier`, the nullifier registry, `Assurance`, the
  `submit_zk_passport_proof` seam), M5 (`05-*` re-execution consensus for EC-7), the Browser/Mobile Light
  Node track (`07-*`, Stage 3 mobile NFC + WASM prover).
- **Invariants:** [`00-overview.md`](00-overview.md). **Prior art (read-only):** `../ubi.chain`,
  `../ubi.agent`, `../ubi.wallet`.

Stage A/B built the deterministic Groth16/BN254 verifier, pinned the **real Self `vc_and_disclose`
verifying key** (nPublic = 20), and wired the on-chain op — but the chain **cannot today accept a
genuine Self-app proof and mint a verified human**. Four independent gaps block it (from the code audit):
the consensus path runs the confident-accept `MockZkVerifier`; the `self_layout` 20-slot mapping is an
unverified guess that is off-by-one from slot 6, zeroes the live signals a real proof carries, and aliases
`attestation_id` over `current_date[5]`; our FNV CSCA sponge is mapped into Self's Poseidon `merkle_root`
slot (a guaranteed mismatch); and the SDK and the Rust adapter disagree on the layout entirely. With the
mock, paste-a-bundle "works" but proves nothing; the moment the real verifier is wired, a genuine Self
proof verifies **false** because the reconstructed public-input vector cannot equal the proof's real
signals.

This spec closes those gaps by **integrating the Self app/SDK as the proof source** (user decision (b):
*Self now, own stack later*), makes ZK-passport the value-minting lead, flag-gates the vouching path off
value-minting (user decision (a)), and ties a passport-verified human to running a light node (user
decision (c): the *human node*). It is written acceptance-criteria-first (§9); every EC maps 1:1 to a test.

---

## 0. The invariants this stage must hold (and the one new trust it honestly imports)

> **I4 (fail-closed), still the spine.** Every new binding — attestation type, scope, `user_identifier`,
> `current_date` freshness, and the Self identity-root membership check — **aborts on the first
> mismatch with no state change**. Uncertainty about a trust anchor denies, never guesses.

> **I1/I2 (deterministic, reproducible).** The Groth16 verify is pure field/pairing arithmetic over a
> fixed 20-element public vector; the accepted Self-root set, the pinned scope, and the freshness window
> are **committed consensus state** read only from `block.timestamp` and the state, so two nodes reach
> the identical accept/reject and identical post-state. It rides the M5 re-execution consensus (EC-7),
> no AI quorum — the cleanest realization of I1.

> **The one new trust, stated plainly (the crux — §2).** A genuine Self disclosure proof commits to the
> root of **Self's own on-chain identity-commitment registry** (the Poseidon Lean IMT their registration
> circuit populates after passive-authentication against the CSCA/DSC trees), **not** to our CSCA
> governance registry. To accept a real Self proof, ubi2 must **track and pin Self's registry root(s)**
> as external trust anchors. This imports **Self's registration + registry-root authority + their TEE
> OFAC-root updater** into ubi2's trust base. That is a residual centralization/liveness dependency. It
> is accepted **deliberately and temporarily** under decision (b): Self carries the sovereign-PKI plumbing
> now; standing up an **independent NFC + register circuit + CSCA masterlist + trusted-setup ceremony** —
> which returns the `merkle_root` slot to *ubi2's own* registry root and removes this dependency — is the
> named hardening milestone (§7 DEFERRED, O-C1). The inclusion constraint doubles as the mitigation: the
> chain is never single-rooted on Self because the (flag-gated, testnet) social path still exists, and
> mainnet value-minting can be held to ZK-only until the own-stack ceremony lands.

The three structural rules from spec 06 are unchanged: `crates/runtime` stays deterministic and
dependency-free (the verifier lives in `crates/zkpoh`), heavy proving is client-side (now: **the Self
app**), and there is no new consensus primitive (the op rides HumanityHub + M5 re-execution).

---

## 1. Scope

**In scope (Stage C):**
1. **Registry-model reconciliation (§2)** — a governance-pinned **Self identity-root registry** (+ the
   three OFAC SMT roots) replacing the CSCA-root-in-`merkle_root` mapping, with a deterministic
   accepted-root **window**; the honest trust accounting.
2. **The canonical ubi2 scope (§3)** — one network-wide scope so one passport ⇒ exactly one nullifier
   on ubi2 (Sybil key), pinned and bound.
3. **Public-input reconciliation (§4)** — fix `self_layout` to Self's **real** 20-signal
   `vc_and_disclose` order; carry the **full** `publicSignals[20]` on-chain; bind the policy-relevant
   slots; wire the **real `Groth16Verifier`** onto the consensus path (pure crypto, no AI).
4. **The Self client flow (§5)** — replace paste-a-bundle with the Self SDK (`SelfAppBuilder` v2 →
   QR/deeplink → the Self app returns `{attestationId, proof, publicSignals, userContextData}` → the
   wallet encodes `submitZkPassportProof` → MetaMask-signed tx).
5. **Vouching flag-gate (§6)** — a committed genesis flag that takes the social path **off the
   value-minting transition** (testnet-only), preserving determinism and every M3 test.
6. **Human-node tie-in (§7.human-node)** — a passport-verified human runs the Browser/Mobile Light Node
   (light-node Stage 3): one app, one proven human, one independently-verifying node.

**Out of scope / DEFERRED (own-stack hardening, §7):**
- ubi2's **own** NFC read + register circuit + CSCA masterlist + multi-party **trusted-setup ceremony**
  (the milestone that removes the Self trust dependency — O-C1).
- On-chain verification by **bridging** a Self attestation from Celo (we verify **off-chain-replayably**
  in-runtime instead — §2.3).
- Active/Chip Authentication anti-clone; retroactive purge of nullifiers under a retired Self/OFAC root;
  additional Self document types (EU ID `attestationId=2`, Aadhaar `=3`) — the layout constants differ
  per document (O-C4).
- Replacing the M3 vouching path — it is flag-gated, never deleted.

---

## 2. Registry-model reconciliation (THE crux) — track Self's identity root, not our CSCA sponge

### 2.1 The problem, precisely

Self is two circuits (Semaphore-style). A **register** circuit does passive-authentication in-ZK
(verifies the SOD/DSC signature, that the DSC chains to a CSCA in Self's on-chain DSC/CSCA trees) and
inserts a Poseidon **identity commitment** into Self's on-chain **Lean IMT**. The **disclose** circuit
(`vc_and_disclose`) later proves membership of a leaf in **that commitment tree** and selectively
reveals DG1 fields. The disclose proof's `merkle_root` public signal is therefore **the root of Self's
identity-commitment registry** — a Poseidon Lean-IMT root that rotates as registrations arrive. CSCA/DSC
validity was consumed at *registration* time and is only reflected indirectly.

Our Stage-A/B code puts our **FNV-1a-256 CSCA sponge root** into that `merkle_root` slot. Groth16 verify
is an exact equality over public inputs, so a real proof — whose `merkle_root` is Self's Poseidon root —
verifies **false** against our FNV value. **These are cryptographically different objects; the mapping
cannot be made to work.** This is GAP-3.

### 2.2 Decision — adopt Self's trust model for the Self scheme; pin Self's roots as anchors

For `schemeTag = 0` (Self e-passport), the `merkle_root` slot is bound to **membership in a
governance-pinned set of accepted Self identity-commitment roots**, not to our CSCA root. Concretely a
new runtime collection replaces the CSCA registry's role *on the verify path* (the CSCA registry stays
in the codebase, unused by the Self scheme, reserved for the own-stack milestone):

```
SelfRootRegistry (behind the State trait, sorted accessors — same discipline as csca_entries()):
  accepted_identity_roots: sorted set<{ root: [u8;32], pinned_at_block: u64 }>   // Self's Lean-IMT roots
  accepted_ofac_roots:     sorted set<{ kind: u8 (0=passportno,1=namedob,2=nameyob), root: [u8;32],
                                        pinned_at_block: u64 }>                    // Self's 3 OFAC SMT roots
  SELF_ROOT_WINDOW_BLOCKS: u64                                                     // freshness window (O-C3)
```

Governance ops (gated by the same authority M6 uses for `registerCsca`, mirroring M5's validator-set
authority; re-pointed at the DAO in M7):

```
pinSelfIdentityRoot(root, )        // add an accepted identity root (Active from this block)
pinSelfOfacRoot(kind, root)        // add an accepted OFAC SMT root
retireSelfRoot(root)               // drop a root (forward-invalidation; no retroactive nullifier purge — O-C2)
```

The runtime binds, on each proof (§4.4): `publicSignals[merkle_root] ∈ accepted_identity_roots` **and**
each `publicSignals[ofac_*_smt_root] ∈ accepted_ofac_roots[kind]`, where "∈" means the pinned entry is
still within `SELF_ROOT_WINDOW_BLOCKS` of the current height (a pure function of block height — no
wall-clock). Roots rotate; a **single pinned root would reject valid fresh proofs, and accept-any would
lose revocation/OFAC guarantees** — so the window is explicit and root updates are governance events.

### 2.3 How ubi2 (not on Celo) learns Self's roots — off-chain-replayable, deterministic

Self's Hub/registry/PoseidonT3 are deployed only on Celo (mainnet 42220 / Sepolia 11142220). Two paths
were considered; the **off-chain-replayable quorum** is chosen (bridging is deferred, O-C1):

- **(A) CHOSEN — pin + in-runtime re-verify.** An operator (governance) reads Self's current
  IdentityRegistry root(s) from Celo and `pinSelfIdentityRoot`s them on ubi2. Every ubi2 node then
  **independently re-runs the Groth16 verify** against the recorded `{proof, publicSignals}` with the
  genesis-pinned Self VK and checks `merkle_root`/OFAC membership against the pinned set. This is exactly
  the deterministic, offline-replayable pattern ubi2 already uses everywhere: the verdict is a pure
  function of committed state + the calldata; no live external call sits in the consensus path. The
  *liveness* of pinning fresh roots is a governance/operator responsibility (a stale set only fails
  *closed* — new proofs are rejected until a root is pinned; never a safety break).
- **(B) REJECTED for now — bridge the Celo attestation** (Hyperlane/LayerZero, as in Self's boilerplate)
  or call Self's Hub on-chain. Deferred: it puts a cross-chain message or a non-ubi2 chain in the trust
  path and is heavier than the milestone needs. Kept as the eventual production-hardening option.

### 2.4 Trust accounting (for the security gate — do not hide this)

Adopting (A) means ubi2 trusts: (i) Self's registration circuit soundness + its trusted-setup ceremony,
(ii) whoever authors Self's on-chain identity-registry root, (iii) Self's **TEE-authorized OFAC-root
updater**, and (iv) the ubi2 governance operator that pins roots honestly and freshly. This is strictly
more trust than an own-stack CSCA model. It is accepted for the Self-now phase because it retires the
integration risk immediately and because value-minting can be scoped so this trust never single-roots
the chain (the flag-gated social path remains; §6). Removing (i)–(iii) is the own-stack ceremony
(O-C1). This must be a named §11-threat-model line at the M6 Stage-C security gate.

---

## 3. Scope (the Sybil key) — one canonical ubi2 scope, one passport, one human

Self's disclosure nullifier is `nullifier = Poseidon(secret, scope)`: **scope-bound**, so the same
passport under the same scope yields the same nullifier (one-per-app uniqueness) and different scopes are
unlinkable. **Uniqueness on ubi2 therefore holds only if ubi2 uses exactly one scope network-wide.** A
per-context scope would let one human mint multiple identities — the sybil hole this whole milestone
exists to close.

**Decision.** Pin a single canonical ubi2 scope:

```
UBI2_SELF_SCOPE_SEED = "ubi2-poh"          // the human-readable seed (frontend `SelfAppBuilder.scope`)
UBI2_SELF_SCOPE      = <field element>     // the exact scalar the Self off-chain scope derivation
                                           //   produces for that seed — PINNED from a real fixture (§4.5)
```

- We verify **off-chain** (§2.3), so the scope is Self's off-chain scope derivation over the scope
  string/endpoint — **not** the on-chain `PoseidonT3(addressHash, scopeSeed)` form (that binds to a
  verifier *contract address*, which we do not deploy). The frontend passes `scope: "ubi2-poh"`; the
  runtime binds `publicSignals[scope] == UBI2_SELF_SCOPE`; a proof under any other scope is rejected.
- The current `SELF_SCOPE_CONST = 0x75626932` ("ubi2") is a **guess** and must be replaced by the value
  a real Self proof carries in the scope slot for our seed (O-C5). The mechanism is pinned here; the
  numeric constant is pinned from the fixture that §9 EC-C7 verifies end-to-end.
- Because the nullifier binds to the passport + this one scope, `nullifier` (slot 6, §4) is the permanent
  one-passport-one-human registry key — the same permanence + canonicality guard M6 Stage B already
  enforces (`is_canonical_scalar`, `put_nullifier`) carries over unchanged.

> **Note — replaces ADR-0005 D3's chain-bound derivation.** Stage A defined
> `nullifier = H_circuit(document_secret ‖ CHAIN_ID ‖ SCHEME_TAG)`. A real Self proof does not compute
> that; it computes `Poseidon(secret, scope)`. We adopt Self's derivation and get per-chain
> unlinkability from **scope** instead of `CHAIN_ID`. Recorded in §11.

---

## 4. Public-input reconciliation — the real 20-signal layout, full-vector carriage, real verifier

### 4.1 The real `vc_and_disclose` public-signal order (arkworks/snarkjs order)

We verify with arkworks against the VK, so the authoritative order is **snarkjs's**: circuit **outputs**
in declaration order, then the **declared public inputs**. For `VC_AND_DISCLOSE` at nPublic = 20
(`IC.len() == 21`), with `forbidden_countries_list_packed` = 3 field elements:

| Slot | Signal | Bound by the runtime to… |
|---|---|---|
| 0,1,2 | `revealedData_packed[3]` | stored **opaquely** as our 3 attribute commitments (I6) — pass-through |
| 3,4,5 | `forbidden_countries_list_packed[3]` | pass-through (proof-tied; not our policy key) |
| **6** | `nullifier` | canonicality guard + uniqueness registry key (§3) |
| **7** | `merkle_root` | **∈ accepted Self identity roots** (§2.2) — NOT our CSCA root |
| **8** | `ofac_passportno_smt_root` | ∈ accepted OFAC roots kind 0 (§2.2) |
| **9** | `ofac_namedob_smt_root` | ∈ accepted OFAC roots kind 1 |
| **10** | `ofac_nameyob_smt_root` | ∈ accepted OFAC roots kind 2 |
| **11** | `scope` | `== UBI2_SELF_SCOPE` (§3) |
| **12** | `user_identifier` | `== submitter address` (tx sender) — anti-replay (§4.4) |
| 13..18 | `current_date[6]` (YYMMDD ASCII) | freshness window around `block.timestamp` (§4.4) |
| **19** | `attestation_id` | `== 1` (E-Passport) for `schemeTag = 0` |

> **This is provisional until a real staging proof confirms it (O-C5).** The 20-vs-21 count and the exact
> per-slot order differ between Self's on-chain re-packed `pubSignals[21]` and the circuit's snarkjs
> order, and shift by document type. The **pinned mechanism** is: derive the order from the compiled
> circuit `.sym` **and** a genuine Self staging proof's `publicSignals`, and treat EC-C7 (a real proof
> verifying end-to-end) as the test that actually validates it. Do not hardcode against the current
> guess.

### 4.2 Fixes to the current code (the four audit gaps)

- **GAP-2 (self_layout):** replace the off-by-one guessed indices with §4.1. Current
  `NULLIFIER=7/MERKLE=8/SCOPE=12/USER=13/CURRENT_DATE=14/ATTESTATION_ID=19` collides `current_date[5]`
  onto `attestation_id`; the corrected map (nullifier 6, merkle 7, ofac 8–10, scope 11, user 12,
  current_date 13–18, attestation 19) has no collision.
- **The zeroing bug:** the adapter zeroes slots 3,4,5 (forbidden countries) and 8,9,10 (OFAC roots). A
  real proof carries **live nonzero** values there; zeroing them guarantees the MSM cannot match. The
  runtime must consume the **actual** signal values (§4.3), not synthesize them.
- **GAP-3 (merkle_root):** §2 — bind slot 7 to Self-root membership, not our CSCA sponge.
- **GAP-4 (SDK ↔ Rust divergence):** dissolved by §4.3 — the SDK no longer extracts policy fields by
  index; it passes the whole vector. The only index the SDK reads is `nullifier` (slot 6) for the
  pre-check display, and it imports the slot constant from a single shared source
  (`packages/sdk` mirrors `crates/zkpoh::self_layout` constants; a fixture test asserts both parse an
  identical proof identically).

### 4.3 Data-model change — carry the FULL `publicSignals[20]` on-chain

Because a real proof's public vector is fixed by the circuit, the runtime cannot reconstruct it from six
domain fields; it must receive it. The `submitZkPassportProof` calldata becomes **proof + the full
20-element public vector**; the runtime derives the policy fields by index and binds them:

```solidity
// supersedes the Stage-B op shape (devnet-only; no mainnet nullifiers exist yet — clean replacement,
// pinned as ADR-0008). MetaMask-signable; submitter is ecrecover(tx.sig), never in calldata.
function submitZkPassportProof(
    bytes       proof,            // Groth16 A,B,C over BN254 (canonical bytes; ~256B)
    bytes32[20] publicSignals,    // the REAL vc_and_disclose public vector, snarkjs order (§4.1)
    uint8       schemeTag         // 0 = Self e-passport (attestation_id must be 1)
) external;
```

The runtime side:
- `ZkPublicInputs` gains a `signals: [Hash; SELF_NPUBLIC]` field (the raw vector). `crates/zkpoh`
  converts each to `Fr` by the single canonical mapping and verifies against the pinned VK — no adapter,
  no zeroing.
- `ZkProofSubmission` carries `proof` + `signals` + `scheme_tag`. The derived values the lifecycle uses —
  `nullifier = signals[6]`, `attribute_commitments = [signals[0], signals[1], signals[2]]` — are read by
  index, not passed separately (removes the cross-check surface).
- The nullifier **canonicality guard** and **uniqueness pre-check** run on `signals[6]` exactly as today
  (before the pairing — F-5).

### 4.4 Verification algorithm (deterministic; fail-closed at every step)

On a `submitZkPassportProof` tx at block `B` (extends spec 06 §4.2; every step a pure function of state +
the tx + `B.timestamp`):

1. **Bound-check:** `schemeTag == 0`; `proof` length and `publicSignals.len() == 20`. Else reject.
2. **attestation_id:** `signals[19] == 1` (E-Passport). Else `UnexpectedAttestation`.
3. **scope:** `signals[11] == UBI2_SELF_SCOPE`. Else `WrongScope` (would be a different-app nullifier).
4. **submitter binding:** `signals[12] == submitter address` (tx sender). Else `SubmitterMismatch`
   (anti-replay / front-run, F-4). *(The Self proof was requested with `userId = the ubi2 address`, §5.)*
5. **freshness:** decode `signals[13..18]` (YYMMDD) to a day; require it within
   `[B.timestamp − SELF_DATE_WINDOW, B.timestamp]` (a deterministic block-time window; O-C3). Else
   `StaleProofDate`. *(Ties the in-circuit not-expired check to chain time; F-1.)*
6. **trust anchors:** `signals[7] ∈ accepted_identity_roots` (within window) **and** each of
   `signals[8..10] ∈ accepted_ofac_roots[kind]` (within window). Else `UntrustedSelfRoot` /
   `UntrustedOfacRoot` (EC-3 analogue; F-2).
7. **nullifier canonicality:** `is_canonical_scalar(signals[6])`. Else `NonCanonicalNullifier`.
8. **nullifier uniqueness (cheap, before the pairing — F-5):** `signals[6] ∉` the nullifier registry.
   Else `NullifierAlreadyUsed`.
9. **status/idempotency guard:** existing `Revoked` → `SubjectRevoked`; existing `Enh`/`Dual` →
   `AlreadyEnhanced` (F-9).
10. **SNARK verify (the pure crypto):** `Groth16Verifier::verify_passport(proof, signals)` against the
    genesis-pinned Self VK. `false` ⇒ `InvalidProof` (F-3). **No partial state on false.**
11. **Commit atomically (success only):** insert `signals[6]` (nullifier); store
    `[signals[0..3]]` as the opaque attribute commitments; set assurance (new → `Enh` + start emission
    exactly as `finalize_registration`; `Std`-Verified → `Dual`, balance + `verified_at` untouched); emit
    the PoH-NFT metadata update. Identical accept/reject + post-state on every node ⇒ `state_root` agrees
    (M5 EC-4/EC-10).

### 4.5 The real verifier goes on the consensus path (pure crypto, no AI)

**Decision (GAP-1).** The consensus default for the ZK path becomes the real
`Groth16Verifier::from_pinned()` (genesis-pinned Self VK), wired in `crates/node` via
`Chain::with_verifier(Arc::new(...))`. The `MockZkVerifier` stays the **CI/lifecycle** default (I5,
scripted booleans) and the EC-7 injected-disagreement stub — never the value-minting default.

- ZK verification is pure deterministic cryptography; it needs **no AI quorum** and slots directly into
  the M5 re-execution consensus (EC-7): every follower re-runs the pairing and agrees to the bit; a
  divergent verifier computes a different `state_root` and is out-voted (spec 06 §5.4, ADR-0005 D5).
- **Guardrail (O-C6):** wire the real verifier as the value-minting default only after (a) the §4.1
  layout fix lands and (b) **EC-C7** — a genuine Self **staging** proof verifies end-to-end through
  `submit_zk_passport_proof`. Until (b) passes on real bytes, mainnet-value onboarding stays ZK-gated on
  a confirmed VK, and testnet may run the staging VK + `mockPassport=true` Self endpoint. The pinned VK's
  **byte-identity to Self's production `vc_and_disclose` VK** is an explicit prerequisite (O-C5): today we
  pin a fixture VK; a proof under Self's **production** zkey is not yet in the open repo.

---

## 5. The Self client flow (replaces paste-a-bundle)

The wallet's "Verify with passport (ZK)" path uses the Self SDK (**pin V2** — `version: 2`; the V1 API
differs). Heavy proving is the Self app on the user's device (no passport bytes touch ubi2 — I6).

### 5.1 Frontend — build the SelfApp and render the handoff (`@selfxyz/qrcode`)

```ts
const app = new SelfAppBuilder({
  version: 2,
  appName: "ubi2",
  scope: "ubi2-poh",                        // the CANONICAL ubi2 scope (§3) — never per-context
  endpoint: UBI2_SELF_ENDPOINT,             // the ubi2 relay that receives the proof (§5.2)
  endpointType: "staging_https",            // OFF-CHAIN verify; staging on testnet, "https" on mainnet
  userId: activeUbi2Address,                // userIdType: "hex" — binds the proof to the ubi2 address
  userIdType: "hex",
  userDefinedData: activeUbi2Address,       // echoed back for the relay to cross-check
  disclosures: {
    minimumAge: 18,                         // over-18 predicate (feeds the over18 gate, §7 Stage D)
    ofac: true,                             // sanctions check (binds the 3 OFAC roots, §2/§4.4 step 6)
    excludedCountries: UBI2_EXCLUDED,       // policy list → forbidden_countries slots
    nationality: true,                      // nationality bucket → a revealedData slot (opaque on-chain)
  },
}).build();
// render <SelfQRcodeWrapper selfApp={app} onSuccess={...} onError={...} /> and getUniversalLink(app)
```

- **`endpointType` is a security boundary:** `staging_*` accepts **mock/test** passports; `https`/`celo`
  accept only real passports. Testnet uses `staging_https`; mainnet uses `https`. The runtime must know
  which VK/root-set is live per network (a mismatch lets a test passport pass a production check — O-C5).
- `userId = the ubi2 address` is what makes step §4.4-4 (`user_identifier == tx sender`) enforceable — a
  copied proof cannot be relayed by a different account.

### 5.2 The ubi2 relay endpoint — a thin, trustless encoder

The Self app POSTs `{ attestationId, proof, publicSignals, userContextData }` to `UBI2_SELF_ENDPOINT`
(the wallet's local relay, or a node RPC). The relay:
1. shape-checks the payload and that `userContextData` echoes the expected ubi2 address;
2. ABI-encodes `submitZkPassportProof(proof, publicSignals[20], schemeTag=0)` (§4.3);
3. returns the calldata to the wallet for **MetaMask signing** (the tx sender = the bound address), or —
   for the embedded devnet wallet — signs with the local key.

The relay is **not trusted**: the runtime re-verifies the proof and re-binds every slot. A lying relay
can at worst produce a tx that the chain rejects fail-closed. (Optionally the relay also runs the
`@selfxyz/core` `SelfBackendVerifier` for instant UX feedback, but that verdict is advisory — the chain's
in-runtime verify is authoritative.)

### 5.3 Dev/CI fallback (no live Self app)

Keep a **fixture path**: a recorded genuine Self **staging** proof bundle (`{proof, publicSignals}`) plus
the paste/upload UI as a developer fallback, so CI and offline dev exercise the full flow without the
mobile app (EC-C7 uses this fixture). The paste path is **dev-only** and clearly labeled; it submits the
identical calldata, so it is not a second trust surface.

### 5.4 SDK changes (`packages/sdk/src/passport.ts`)

- `encodeSubmitZkPassportProof` takes `proof` + `publicSignals: Hex[20]` + `schemeTag` (drop the separate
  `nullifier`/`attributeCommitments`/`cscaRegistryRoot` args — they are now derived on-chain).
- Extract-by-index helpers reduce to `extractNullifier(bundle) = signals[6]` (for the `ubi_isNullifierUsed`
  pre-check display only); the slot constants are imported from one shared module mirrored to
  `self_layout.rs` (§4.2 GAP-4).
- Add the `@selfxyz/qrcode` `SelfAppBuilder` wiring (§5.1) behind the same module. Pin `@selfxyz/qrcode`,
  `@selfxyz/core` versions hard.

---

## 6. Vouching flag-gate — off the value-minting path, testnet-only (user decision (a))

**Decision.** ZK-passport leads; the social path is retained but **gated off the value-minting
transition** by a committed genesis flag.

- Add a genesis config value `vouching_enabled: bool`, threaded exactly like `csca_governance`
  (`MemState` field → `Chain::set_vouching_enabled` → `persist.rs`/`snapshot.rs` DTO →
  `State::vouching_enabled()`), and **folded into the `state_root` config header** so a divergent flag is
  a divergent root (out-voted, never silent). **Default = `true`** so every existing M3 test — none of
  which sets the flag — stays byte-identically green.
- **The load-bearing gate is `finalize_registration`** (the transition that flips
  `Account.verified`/`verified_at` and starts emission — the *value-minting* step). When
  `vouching_enabled == false` it returns a new `LifecycleError::VouchingDisabled` and mutates nothing.
  `request_verification` and `vouch` gate on the same flag to fail early (no juror work, cleaner UX).
- **`submit_zk_passport_proof` is never gated** — the ZK path is unaffected. A human who onboarded via
  vouching on a testnet where it was later disabled keeps their `Verified` status (the flag gates the
  *transition*, not existing state); mainnet simply ships with the flag off from genesis, so no vouching
  human is ever minted there until governance (M7) flips it.
- Determinism: the flag is consensus state read purely from `State`; the gate is a pure branch. No
  wall-clock, no float. Two nodes with the same genesis agree.

This satisfies (a): on the mainnet/value genesis the flag is `false`, so **no vouching-based address can
reach emission**; ZK-passport is the sole value-minting onboarding until the own-stack ceremony and/or M7
governance re-enables a hardened social path. On testnet the flag is `true` for inclusion testing.

---

## 7. Human node, staged delivery, and REAL-vs-DEFERRED

### The human node (user decision (c))

A **human node** = a passport-verified human running the Browser/Mobile Light Node. The coupling is
already structural:

- The **same mobile app** that generates the Self proof is the light-node track's **Stage 3** wrapper
  (on-device NFC via the Self app + WASM re-execution light client). Completing ENH verification and
  running the light node are the same install.
- The light node already **re-executes the full chain and matches `state_root` byte-for-byte**
  ("trust no server", spec 07). A human node therefore both (i) verifies the chain independently and
  (ii) has a proven-unique-human operator (its funding/identity address is `Enh`/`Dual`).
- **M6 scope is identification, not consensus weight.** A human node does **not** gain block-production
  or voting power in M6 (that stays with M5 validators). The deliverable is: the light client can read
  its operator's assurance level and surface an "independently-verified by a verified human" status, and
  the node advertises its operator address so a future proof-of-personhood weighting (M7/backlog) has the
  substrate. Any consensus weight from human nodes is **DEFERRED** (O-C7) — introducing it now would make
  PoH a consensus primitive, which I1 forbids without its own gate.

### Staged delivery (Stage C sub-stages)

**C0 — reconciliation + real verifier (the correctness core).**
- C0.1 Fix `self_layout` to §4.1; add `SELF_NPUBLIC` full-vector carriage to `ZkPublicInputs` /
  `ZkProofSubmission`; drop the adapter/zeroing. Update the op ABI (§4.3).
- C0.2 `SelfRootRegistry` (§2.2) + `pinSelfIdentityRoot`/`pinSelfOfacRoot`/`retireSelfRoot` governance
  ops + the accepted-root window; new bind steps (§4.4 steps 2,3,5,6).
- C0.3 Wire `Groth16Verifier::from_pinned()` onto the consensus path via `Chain::with_verifier` (§4.5),
  behind the EC-C7 guardrail; keep `MockZkVerifier` for CI.
- C0.4 Pin `UBI2_SELF_SCOPE` from a real staging fixture (§3/§4.5).

**C1 — Self client flow (§5).** SelfAppBuilder v2 wiring, the relay endpoint, MetaMask handoff, the
dev/CI fixture fallback; SDK changes (§5.4).

**C2 — vouching flag-gate (§6).** Config flag + `finalize_registration`/`request_verification`/`vouch`
gates + `state_root` config-header fold + DTO threading.

**C3 — human-node tie-in.** Light client reads operator assurance; the mobile app couples Self proof +
light node (light-node Stage 3 dependency).

### REAL vs DEFERRED (explicit)

| Area | REAL in Stage C | DEFERRED (own-stack / hardening) |
|---|---|---|
| Proof source | The Self app/SDK (V2), off-chain-replayable verify in-runtime | ubi2's **own** NFC + register circuit + trusted-setup ceremony (O-C1) |
| Trust anchor | Governance-pinned **Self identity + OFAC roots**, windowed | ubi2's own CSCA masterlist as `merkle_root` (needs own circuit) |
| Verify locus | In-runtime Groth16 over recorded `{proof, publicSignals}` | On-chain bridge of a Celo attestation (O-C1) |
| Anti-clone | Passive Authentication (Self) | Active/Chip Authentication (O-C4) |
| Documents | Passport (`attestation_id = 1`) | EU ID (=2), Aadhaar (=3) — different layouts (O-C4) |
| Revocation | Forward-invalidation via `retireSelfRoot` | Retroactive nullifier purge under a retired root (O-C2) |
| Human node | Identification (operator assurance surfaced) | Consensus weight / proof-of-personhood weighting (O-C7) |

---

## 8. New / changed interface surface

- **Write (HumanityHub, MetaMask-signable):** `submitZkPassportProof(bytes proof, bytes32[20]
  publicSignals, uint8 schemeTag)` (§4.3, supersedes the Stage-B shape). `pinSelfIdentityRoot(bytes32
  root)`, `pinSelfOfacRoot(uint8 kind, bytes32 root)`, `retireSelfRoot(bytes32 root)` — governance-gated
  (§2.2). The Stage-B `registerCsca`/`revokeCsca` remain (unused by the Self scheme; reserved for the
  own-stack milestone).
- **Read (`ubi_*`):** `ubi_getSelfRoots()` → `{ identityRoots, ofacRoots, windowBlocks }` (so a client can
  confirm the live trust set before requesting a proof); `ubi_isNullifierUsed(nullifier)` unchanged;
  `ubi_getAttributes`/`ubi_getHuman` assurance unchanged. `ubi_getCscaRegistry` retained but marked
  reserved.
- **EVM compat (I3):** the op is a HumanityHub tx with a fixed selector (MetaMask signs unchanged); all
  reads are `ubi_*` extensions; **no `eth_*` semantics change.** The larger calldata (`bytes32[20]`)
  raises `GAS_ZKPOH`; still a single HumanityHub op.

---

## 9. Acceptance criteria (1:1 with tests)

CI uses `MockZkVerifier` for lifecycle/composition and a **recorded genuine Self staging proof fixture**
for the real-crypto criteria (EC-C7). Multi-node criteria reuse the M5 harness.

| AC | Assertion (the test bar) | Sub-stage |
|---|---|---|
| **EC-C1** | `self_layout` places nullifier@6, merkle_root@7, ofac@8–10, scope@11, user_identifier@12, current_date@13–18, attestation_id@19; the mapping is pure and has **no slot collision** (attestation_id is not overwritten). A round-trip test asserts the 20-vector reproduces a fixture proof's `publicSignals` exactly. | C0 |
| **EC-C2** | With the **real `Groth16Verifier`** and the Self staging VK, a proof whose `merkle_root` is **not** in `accepted_identity_roots` (or outside the window) is rejected `UntrustedSelfRoot`, fail-closed, no state change. After `pinSelfIdentityRoot(root)`, a proof carrying that root is accepted. Same for each OFAC root. | C0 |
| **EC-C3** | A proof whose `scope` ≠ `UBI2_SELF_SCOPE` is rejected `WrongScope`; a proof whose `user_identifier` ≠ the tx sender is rejected `SubmitterMismatch` (copied/relayed proof, F-4); a proof whose `attestation_id` ≠ 1 is rejected `UnexpectedAttestation`. Each fail-closed. | C0 |
| **EC-C4** | Two proofs from the **same passport** under the canonical scope carry the **same** `nullifier`; the second submission (any address) is rejected `NullifierAlreadyUsed` chain-wide, identical on all nodes (state_root unchanged) — one-passport-one-human on ubi2. | C0 |
| **EC-C5** | A `current_date` outside the freshness window is rejected `StaleProofDate`; a non-canonical `nullifier` (≥ r) is rejected `NonCanonicalNullifier` before the pairing. | C0 |
| **EC-C6** | The consensus path runs the **real** verifier (not the confident-accept mock): a garbage `proof` with well-formed `publicSignals` verifies **false** → not `Verified`, no emission. (Guards against the Stage-B "mock accepts anything" state.) | C0 |
| **EC-C7** | A **recorded genuine Self staging proof** (produced by the Self app against the pinned scope + a pinned identity root) verifies **true** end-to-end through `submit_zk_passport_proof` and mints an `Enh` `Verified` human that starts emission. This is the test that validates the layout, scope, and VK against real bytes. | C0/C1 |
| **EC-C8** | The Self client flow: `SelfAppBuilder({version:2, scope:"ubi2-poh", userId:addr, ...})` → relay receives `{proof, publicSignals}` → encodes `submitZkPassportProof` → the tx from `addr` is accepted; the same proof relayed from a **different** address is rejected `SubmitterMismatch`. (Fixture-driven in CI.) | C1 |
| **EC-C9** | With `vouching_enabled = false`: `request_verification`/`vouch`/`finalize_registration` return `VouchingDisabled`, no state change, **no address reaches emission via vouching**; `submit_zk_passport_proof` still mints `Enh`. With `vouching_enabled = true` (the default): the **entire M3 suite stays byte-identically green**. | C2 |
| **EC-C10** | The `vouching_enabled` flag is folded into `state_root`: two nodes with opposite flags compute **different** roots; a node with the wrong flag diverges and is out-voted (reuses M5 fork-choice). | C2 |
| **EC-C11** | On the multi-node harness (M5 Stage C), a real `submitZkPassportProof` is gossiped, included, and **every follower re-executes the real Groth16 verify**; agreement commits; an injected-disagreement node (stubbed verifier) diverges and is out-voted; no partial state (EC-7). | C0 + M5 Stage C |
| **EC-C12** | A passport-verified human running the light node: the light client reads its operator address's assurance (`Enh`/`Dual`) and surfaces it, while still matching `state_root` byte-for-byte; the human node has **no** block-production/voting power (asserted absent). | C3 |
| **EC-C13** | `ubi_getSelfRoots()` returns the live pinned identity + OFAC roots and window; a non-governance `pinSelfIdentityRoot`/`retireSelfRoot` is rejected `NotGovernance`; a newly-pinned root is **immediately usable** by the next proof (EC-10 analogue). | C0 |

### 9.1 Failure-mode ACs (also pass)

| AC | Failure mode | Assertion |
|---|---|---|
| **EC-F-C1** | Test passport on production endpoint | A `staging`/mock proof is rejected on a node configured for the production VK/root-set (endpoint-type ↔ VK mismatch guarded — O-C5). |
| **EC-F-C2** | Stale Self root | A proof carrying a once-valid identity root that has aged past the window (or been `retireSelfRoot`-ed) is rejected `UntrustedSelfRoot`; already-minted nullifiers are **not** retroactively purged (O-C2, documented). |
| **EC-F-C3** | Relay tampering | A relay that alters any `publicSignals` slot produces a tx the runtime rejects fail-closed (Groth16 verify false or a bind mismatch) — the relay is not a trust surface. |
| **EC-F-C4** | Vouching re-enable | Flipping `vouching_enabled` false→true (governance) restores the M3 path deterministically; existing ZK humans unaffected. |

---

## 10. Threat model deltas (for the security gate)

- **Imported Self trust (§2.4)** — the central new risk: Self registration soundness + ceremony, Self's
  identity-root authorship, and Self's TEE OFAC updater are now in ubi2's trust base. Mitigations: the
  windowed pinned-root set (fail-closed on staleness), the flag-gated social path so the chain is not
  single-rooted, and the named own-stack removal milestone (O-C1). **Must be an explicit gate line.**
- **Scope misconfiguration** — a per-context or wrong scope breaks one-passport-one-human. Mitigation:
  one pinned `UBI2_SELF_SCOPE`, bound in-runtime (EC-C3), pinned from a real fixture (EC-C7).
- **Config/disclosure lockstep** — if the frontend `disclosures` (minimumAge/ofac/excludedCountries) and
  the runtime's bound checks (OFAC-root membership, attestation, scope) drift, a weaker proof could pass.
  Mitigation: the runtime binds the OFAC roots + attestation + scope on-chain (§4.4), independent of the
  frontend; the frontend config only affects what the Self app *offers*, never what the chain *accepts*.
- **Endpoint-type / VK / network confusion** — `staging` accepts mock passports. Mitigation: pin the VK
  + root-set per network; reject a staging proof on a production node (EC-F-C1, O-C5).
- **Real verifier on consensus** — a divergent/patched pairing impl forks a node. Mitigation: the M5
  re-execution consensus contains it (out-voted), and arkworks is pinned deterministic + canonical-encoding
  (ADR-0005 D2), unchanged here.
- **Larger calldata DoS** — `bytes32[20]` + a real pairing per tx. Mitigation: `GAS_ZKPOH` sized up, the
  cheap nullifier/scope/attestation pre-checks before the pairing (§4.4 ordering), and non-fee-exemption
  (spec 06 §4.1, O-1 unchanged).

---

## 11. Decisions that amend ADR-0005 (recorded honestly; ratify in ADR-0008 — O-C6)

1. **Nullifier derivation (amends D3).** Adopt Self's `Poseidon(secret, scope)` scope-bound nullifier;
   per-chain unlinkability now comes from the pinned `UBI2_SELF_SCOPE`, not an in-circuit `CHAIN_ID`
   mixin. The permanence + canonicality guard + registry are unchanged.
2. **Trust anchor (amends D1/§7).** For the Self scheme, `merkle_root` binds to a **governance-pinned Self
   identity-root set** (+ OFAC roots), not to ubi2's CSCA sponge. The CSCA registry is retained but
   inactive on the verify path, reserved for the own-stack milestone. This imports Self's trust (§2.4).
3. **Public-input layout (amends D1/§3.5).** The pinned vector is Self's **real** 20-signal
   `vc_and_disclose` order carried in full on-chain, not our 8-field domain vector. `attestation_id == 1`;
   `schemeTag` stays ubi2's own document-family discriminant, decoupled from the circuit signal.
4. **Attribute commitments (amends D4).** The three on-chain commitments are Self's `revealedData_packed`
   slots (opaque, I6-preserving); over-18/nationality/OFAC are proven as **Self disclosure predicates at
   proof time** (via `disclosures`), which changes the Stage-D `over18` design (it may reduce to reading a
   disclosed predicate rather than a bespoke ubi2 Pedersen-opening circuit — revisit at Stage D, O-C4).
5. **Verifier default (amends D2 wiring).** The real `Groth16Verifier` is the **value-minting consensus
   default** (behind the EC-C7 guardrail); `MockZkVerifier` is demoted to CI/lifecycle only.

---

## 12. Open questions (to the orchestrator / security gate)

- **O-C1 — own-stack ceremony (the trust-removal milestone).** Stand up ubi2's own NFC + register circuit
  + CSCA masterlist + multi-party trusted setup, returning `merkle_root` to ubi2's own registry root and
  removing the Self dependency (§2.4). Scope + timing = a milestone decision (post-M6).
- **O-C2 — retroactive revocation.** Purging nullifiers minted under a later-retired Self/OFAC root is
  deferred; M6 does forward-invalidation only (§2.2, spec 06 §7.4).
- **O-C3 — `SELF_ROOT_WINDOW_BLOCKS` + `SELF_DATE_WINDOW`.** Freshness widths (root staleness, proof-date
  skew). Devnet starting constants tuned at the gate.
- **O-C4 — additional documents + Stage-D attribute design.** EU ID/Aadhaar layouts differ; and whether
  `over18` reads a Self disclosure predicate vs a bespoke opening circuit (amendment 4).
- **O-C5 — VK/scope/layout provenance.** Confirm our pinned VK is byte-identical to Self's **production**
  `vc_and_disclose` VK; pin `UBI2_SELF_SCOPE` + the 20-slot order from a real staging proof; guard the
  staging↔production VK/endpoint pairing per network (EC-C7, EC-F-C1). This is the load-bearing
  prerequisite before mainnet value-minting.
- **O-C6 — ratify ADR-0008** for the §11 amendments (costly-to-reverse: the scope, the pinned VK, the
  Self-root trust model, and the op ABI all interoperate forever once a nullifier is minted on a value
  chain).
- **O-C7 — human-node consensus weight.** Whether/how a proof-of-personhood weighting for human nodes
  enters consensus (M7/backlog); deliberately out of M6 to keep PoH off the consensus primitive path (I1).

---

## 13. Determinism checklist (the reliability gate will assert each)

1. The real `Groth16Verifier` is pure + deterministic + canonical-encoding over the full 20-vector — same
   inputs ⇒ same bool on every node (§4.5, ADR-0005 D2).
2. Every new bind (attestation, scope, submitter, freshness, Self-root membership) reads **only** `State`
   + `block.timestamp` — no wall-clock, no float (§4.4).
3. `SelfRootRegistry` + the nullifier registry iterate in **sorted** order into `state_root`; the
   `vouching_enabled` flag is folded into the `state_root` config header (§6) — a divergent flag/root is a
   divergent root, out-voted (EC-C10).
4. `crates/runtime` pulls no crypto/async dep (calls `zkpoh` via the trait); `crates/zkpoh` pulls no
   async/network/clock/float dep — the build-level assertion is unchanged.
5. The Self VK, `UBI2_SELF_SCOPE`, the 20-slot layout, and the accepted-root genesis set are **pinned**
   and committed; a change is a new root / a consensus migration, never silent (state-root header already
   at `ubi2/state-root/3`; the config-flag + Self-root sections extend it).
6. EC-C11's cross-node guarantee is the M5 re-execution consensus (no new primitive); divergence is
   out-voted deterministically.
7. CI runs the full lifecycle on `MockZkVerifier` (I5) plus the focused **real Self staging proof**
   soundness test (EC-C7) — the crypto path is exercisable offline from a recorded fixture.
