# V2 holder credential commitment and issuance transcript

- **Status:** implemented holder/reference candidate; production commitment/hash profile, issuer authentication
  and presentation circuits remain unratified
- **SDK:** [`zk-holder-credential.ts`](../../packages/sdk/src/zk-holder-credential.ts)
- **Private handoff:** [`v2-holder-reference-handoff.md`](v2-holder-reference-handoff.md)
- **Circuit reference:** [`holder_credential.rs`](../../tools/v2-crypto-bench/src/holder_credential.rs)
- **Parent:** [`10-evm-zk-identity-v2.md`](10-evm-zk-identity-v2.md)
- **Cross-lane boundary:** [`ADR-0012`](adr/0012-v2-cross-lane-interface-freeze.md)

## Purpose and boundary

After one passport enrollment, the holder retains an encrypted device-private credential and later proves
age, nationality, issuing state, expiry, assurance and dynamic-status predicates locally. The one-time
credential commitment is public at issuance and anchors issuer authorization, allocation, validity and
revocation. It is deliberately absent from the 18 presentation signals, so applications cannot correlate two
presentations through it.

This slice pins a versioned circuit-native holder-commitment candidate, its deterministic vectors and a sanitized
live issuance transcript. It does **not** put passport claims in the NFT, registry, transcript or public signals.
It also does not ratify this measured Poseidon profile or select/simulate a production issuer signature: allocation
under the transitional Self bridge is not by itself a presentation-ready anonymous credential.

## Credential commitment reference profile v1 (candidate)

Identifiers:

```text
private credential:  org.proofofhumanity.zk-private-credential/1
commitment record:   org.proofofhumanity.zk-holder-credential-commitment/1
commitment scheme:   poseidon-bn254-arkworks-0.5-x5-rate2/1
```

The commitment is one canonical BN254 scalar:

```text
C = PoseidonSponge(domain = 1, fields[0..15])
```

The profile is the existing measured arkworks 0.5 BN254 Poseidon configuration: exponent 5, 8 full rounds,
57 partial rounds, rate 2, capacity 1, with `find_poseidon_ark_and_mds` skip-matrices value 0. Zero output is
invalid; a holder must regenerate `credentialBlinding` in the negligible zero-output case. A parameter,
domain, order or encoding change requires a new commitment scheme and private-credential version.

### Exact field order

All bytes32 values are losslessly split into high/low unsigned 128-bit limbs. No bytes32 value is reduced into
one field.

| Index | Field | Encoding and visibility |
|---:|---|---|
| 0–1 | credential domain | high/low limbs of `keccak256("org.proofofhumanity.zk-private-credential")` |
| 2 | credential version | `1` |
| 3–4 | `issuerKeyId` | nonzero bytes32, high/low limbs; public in issuance and presentation governance |
| 5–6 | `statusId` | `0`, then a nonzero `uint32` packed-status slot; private in presentations |
| 7 | `holderSecret` | nonzero canonical BN254 scalar; private |
| 8 | `credentialBlinding` | independent nonzero canonical BN254 scalar; private |
| 9 | date of birth | `YYYYMMDD` as `uint32`; private |
| 10 | nationality | uppercase three-byte code interpreted big-endian; private |
| 11 | issuing state | uppercase three-byte code interpreted big-endian; private and distinct from nationality |
| 12 | expiry date | `YYYYMMDD` as `uint32`; private |
| 13 | document class | `1` = e-passport; private |
| 14 | assurance | `1` = passive authentication, `2` = chip authentication; private |
| 15 | `issuedAtEpoch` | registry-assigned `uint32`; public as presentation signal 16 |

### Normalization and rejection

- Dates use exactly `YYYY-MM-DD`, must be valid Gregorian dates from 1900 through 2500, and expiry must be
  later than birth. They are committed as `YYYYMMDD` integers; no locale or timezone is involved.
- Country values are trimmed, ASCII-uppercased and must be exactly three `A`–`Z` bytes. Production ingestion
  must additionally map the verified passport/Self result to its pinned ISO 3166-1 alpha-3 table version. The
  commitment function does not infer or translate country names.
- `issuerKeyId` is nonzero bytes32. `statusId` is the exact nonzero `uint32` assigned by the packed-status
  registry; arbitrary bytes32 status identifiers are rejected by this commitment version.
- Holder secret and blinding are independently generated, uniformly sampled nonzero BN254 scalars from the
  platform CSPRNG using rejection sampling. Decimal JSON is canonical: no signs, whitespace or leading zeroes.
  Production callers must never reuse the deterministic fixture constants.
- Unknown JSON fields, unsupported document/assurance values and private input larger than 8 KiB fail closed.
- Errors identify the invalid field class but never echo its value.

The input JSON exists only in temporary process/WASM memory. The CLI accepts it only from stdin and returns a
sanitized commitment record. Product code must minimize its lifetime, overwrite mutable buffers where the runtime
permits, drop all references after the call, and encrypt the complete credential with the existing vault before
persistence. JavaScript strings cannot promise deterministic zeroization, so the isolated worker boundary remains
required. No source fixture, log, analytics event or server API may contain live passport claims.

## What the commitment binds

- **Schema and domain:** fields 0–2 plus the outer Poseidon domain prevent cross-protocol/layout confusion.
- **Holder:** `holderSecret` binds future scoped-nullifier derivation; independent blinding prevents equal
  attributes from producing equal commitments.
- **Issuer and issuance:** `issuerKeyId`, the exact allocated status slot and `issuedAtEpoch` are committed. The
  transitional EIP-712 authorization additionally binds chain, bridge, registry-derived duplicate key, subject,
  commitment and Self verifier configuration.
- **Expiry and revocation:** expiry is private in the commitment. `statusId` selects the private packed bit under
  the current public Poseidon root. The root is intentionally not committed, so a holder can refresh a witness
  after activation/revocation publications without reissuing the base credential.
- **Portability:** wallet, passkey, vault id, consumer, chain and presentation policy are absent. Those belong to
  vault authorization or per-presentation binding, not the reusable credential.

## Sanitized live issuance transcript

`buildZkHolderIssuanceTranscript` takes:

1. the circuit-produced commitment descriptor;
2. the current `ZkSelfIssuanceArtifact` and independently configured verification-authority address;
3. allocation evidence decoded by `zkHolderAllocationEvidenceFromReceipt` from the exact issuance-registry
   `CredentialAllocated` log; and
4. optionally, snapshot evidence decoded from `StatusSnapshotPublished` once a checkpoint covers the slot.

It recovers the EIP-712 signer, requires the authorization, commitment descriptor and allocation event to agree
on issuer, commitment, slot and epoch, recomputes the chain/registry issuance domain, and records exact
transaction/block/log coordinates. Snapshot-covered state additionally requires a canonical BN254 root and an
allocation watermark at or above the credential slot. It does not claim the bit will remain active: every proof
still needs a current accepted root and a valid non-revocation witness.

The transcript stores the public/on-chain commitment and transition evidence plus the subject and configured
verification authority. It omits the raw Self nullifier, registry-scoped duplicate key, authorization signature,
passport claims, holder secret and blinding. A domain-separated `transcriptHash` detects local field drift, but is
a stable issuance reference and must remain inside the encrypted holder vault rather than become an application
identifier. It is not an attacker-proof MAC; the vault's AES-GCM authentication protects the persisted record.

Transcript states are intentionally honest:

- `allocated` — the registry consumed the commitment and assigned its slot/epoch;
- `snapshot-covered` — an authenticated publication covers the allocation watermark.

Neither state means a production commitment profile or issuer signature exists. A credential becomes
presentation-ready only if the circuit/verifier lane ratifies this exact commitment scheme (or publishes an
explicit migration) and supplies the separately versioned issuer-authentication artifact for local verification
before vault persistence.

## Public versus private

| Data | Location | Presentation visibility |
|---|---|---|
| commitment, issuer key id, status slot, issuance epoch | canonical issuance transaction/event | absent from the 18 signals except issuer id and epoch |
| allocation/snapshot tx and block references, transcript hash, subject | encrypted local transcript; some source facts are independently public on chain | absent; never use as an app identifier |
| active status root, issuer key id, issuance epoch | existing public signals 5–6, 3–4 and 16 | public and policy/governance bound |
| holder secret, blinding, exact DOB, nationality, issuing state, expiry, document/assurance class | encrypted credential and ephemeral prover witness | private |
| private status slot and packed witness | encrypted credential/witness cache | private |
| raw Self nullifier and registry-scoped duplicate key | verifier-service memory / transient issuance calldata boundary | never returned in the transcript or presentations |
| scoped presentation nullifier | public signal 13 | public only inside its consumer/context/policy scope |

The Proof-of-Humanity NFT remains an ownership/validity/revocation anchor. It contains none of these private
attributes, no credential ciphertext and no credential commitment.

## Compatibility and unchanged shared interfaces

- No Solidity ABI, event or storage format changes.
- The public-signal vector remains exactly 18 fields. The one-time credential commitment is not added.
- Packed status remains a depth-24 Poseidon tree over 256-bit chunks: `1` is unallocated/revoked, `0` is
  allocated/active, low eight status-id bits select the chunk bit and the next 24 select the path.
- The issuance registry continues to accept one nonzero canonical BN254 `credentialCommitment`; existing
  `CredentialAllocated` and `StatusSnapshotPublished` logs feed the transcript helpers.
- The transitional Self bridge remains usable when the holder commits the exact slot/epoch observed before the
  scan and the allocation wins without a race.

## NEEDS-INTEGRATION-DECISION

### Slot/epoch race recovery

The existing transitional PATCH refresh changes `expectedStatusId` and/or `expectedEpoch` while preserving the
old commitment. Reference profile v1 commits both values, so such an artifact is rejected by transcript validation
and cannot create a valid presentation credential. Cross-lane integration must choose one:

1. **Recommit and re-run passport binding after a race.** No ABI change and safest first testnet behavior, but a
   poor experience under contention or epoch rollover.
2. **Reserve a slot/epoch before the passport scan.** Keeps one final commitment, but adds reservation expiry,
   squatting/DoS and abandoned-slot rules to the issuance/status registry.
3. **Two-stage commitment.** Bind a passport proof to a private core commitment, then fold the assigned slot and
   epoch into a final issuer-signed commitment. Best race UX, but changes the Self request, bridge authorization,
   issuer service and circuit relation and therefore needs an explicit integration ADR.

No shared bridge/registry format is changed in this PR. Until a decision merges, a circuit-native path must treat
`UnexpectedStatusId`/`UnexpectedIssuanceEpoch` as re-enrollment, not grant-preserving refresh.

### Issuer authentication artifact

The research circuit measures a Baby-Jubjub/Poseidon signature, but ADR-0010 has not ratified its exact key,
nonce, signature encoding or rotation scheme. The production circuit/verifier lane must freeze that envelope and
publish cross-language vectors. The holder transcript intentionally does not invent opaque signature bytes or
claim registry allocation is equivalent to issuer authentication.

## Deterministic and adversarial evidence

The shared fixture
[`holder-credential-commitment.json`](../../tools/v2-crypto-bench/fixtures/holder-credential-commitment.json)
uses only ISO user-assigned synthetic codes `XAA`/`XAB`. Rust native Poseidon, the R1CS gadget and the SDK's exact
16-field preimage agree on commitment:

```text
0x0e113b98ce937446f2736264862473af1f0222ef413291a6869847d432bb0d05
```

The SDK pins a complete synthetic authorization → receipt allocation → status publication transcript hash:

```text
0x1306ecc277b40d2f14ae5906d511825c4b1147876f920c720f25c2300ca9b491
```

Tests mutate every private field class, signer, commitment, slot, epoch, allocation event, snapshot watermark and
serialized transcript; each mismatch fails closed. CI reproduces the Rust vector byte-for-byte and builds the
WASM commitment export.

The follow-on reference handoff now generates holder material inside an expiring one-shot session, binds this
transcript and produces authenticated ciphertext through the existing credential vault. Its payload is hard-coded
`reference-only-unratified` and `presentationReady: false`; ADR-0012 still forbids live persistence.
