# ADR-0014 — Issuer-authenticated production vault payload and private status-witness refresh

- **Status:** accepted for implementation; internally security- and privacy-approved; not production-approved
- **Date:** 2026-08-25
- **Deciders:** V2 integration lead, architecture/privacy reviewer, security reviewer, reliability reviewer and QA reviewer
- **Payload schema:** `org.proofofhumanity.zk-holder-production-vault-payload/1`
- **Refresh job schema:** `org.proofofhumanity.zk-holder-private-status-refresh/1`
- **Contract vector:** [`fixtures/v2-identity/production-vault-status-v1.json`](../../../fixtures/v2-identity/production-vault-status-v1.json)
- **Review evidence:** [QA](../../reports/qa-v2-vault-status-adr.md),
  [security](../../reports/security-v2-vault-status-adr.md),
  [privacy](../../reports/privacy-v2-vault-status-adr.md) and
  [reliability](../../reports/reliability-v2-vault-status-adr.md)
- **Boundary implementation evidence:** [QA](../../reports/qa-v2-holder-private-status-refresh.md),
  [security](../../reports/security-v2-holder-private-status-refresh.md) and
  [reliability](../../reports/reliability-v2-holder-private-status-refresh.md)
- **Circuit-native engine evidence:** [QA](../../reports/qa-v2-holder-refresh-wasm-engine.md),
  [security](../../reports/security-v2-holder-refresh-wasm-engine.md) and
  [reliability](../../reports/reliability-v2-holder-refresh-wasm-engine.md)
- **Parents:** [ADR-0012](0012-v2-cross-lane-interface-freeze.md),
  [ADR-0013](0013-v2-production-cryptographic-profile.md) and
  [ADR-0011](0011-dynamic-status-freshness.md)

## Decision boundary

V2 will use a new, strict production-intended vault payload which stores all presentation-private credential
material together under the existing AES-256-GCM portable-vault envelope. The payload contains the admitted
profile identifier and parameter digest, the canonical private credential, its commitment, the complete admitted
Schnorr issuer artifact, the immutable sanitized issuance transcript and one replaceable depth-24 packed-status
witness.

Status refresh is a local transformation from one authenticated ciphertext to another. A host downloads the same
bounded set of unkeyed, authenticated full status snapshots for every admitted cohort, then transfers those public
bundles, the encrypted vault and one unlock result into a fresh isolated worker. Only the worker decrypts the vault,
learns which public issuance `statusId` belongs to this vault, selects the chunk, reconstructs the Merkle path and
seals the replacement payload. No remote request or host message may be selected by status slot, chunk index, bit
index, commitment, subject or path.

This ADR ratifies the storage and refresh contracts **for implementation**. The strict runtime parser, private
Worker boundary and circuit-native refresh-engine candidate are now implemented, but this decision does not allow
live credential persistence, admit a proving key or verifier, or authorize a production rollout. Those remain
behind the production-profile gate, independent audits, mobile evidence, recovery testing and the normal
QA/reliability/security gates.

## Context

ADR-0013 made the production cryptographic relation precise, but the existing holder schemas intentionally stop at
a non-presentable synthetic reference payload. Reinterpreting that reference payload would leave two load-bearing
inputs undefined:

1. the issuer's Schnorr public key, nonce commitment and response which authenticate the committed credential; and
2. the packed chunk and 24 siblings which prove that the private status slot is active under the exact governed
   root.

A status witness also ages independently from the signed credential. Treating both as one immutable issuance blob
would force unnecessary passport reissuance on every status publication. Treating the witness as an online
per-holder service request would reveal a stable private status selector and enable observation, correlation and
targeted withholding. The contract therefore separates immutable credential authority from replaceable status
evidence while encrypting both in one atomic vault payload.

## Decision 1 — Exact production vault payload

The plaintext JSON has exactly these top-level fields; unknown or missing fields fail closed:

```text
schema
version
profile
credential
commitment
issuerAuthentication
issuanceTranscript
statusWitness
```

The existing `PortableCredentialVault` remains the outer envelope. The production parser requires its binding to
have exactly `{ schema: payload.schema, rpId }`, with no extra keys. Payload AEAD additional data remains the exact
UTF-8 JSON encoding of `[format,version,"payload",vaultId,schema,rpId]`; after decryption the worker must require
`payload.schema === vault.binding.schema`. The envelope may reveal the generic vault version, random vault id,
payload schema, RP ID, passkey credential identifiers and random wrapping/AEAD metadata. It must not reveal any
nested payload value. The current 256 KiB plaintext limit remains sufficient and unchanged.

### Profile

`profile` contains only:

- `profileId = org.proofofhumanity.v2-crypto.groth16-bn254-poseidon/1`; and
- `parameterManifestSha256 = b328af00b6d2cff39b5796b5abb37019dfaad5952fe23e10ba96913ab2a624bb`.

An implementation must resolve a locally admitted, content-addressed artifact set before decrypting. A matching
identifier without the matching digest is not the selected profile.

### Private credential and commitment

`credential` is the canonical decimal JSON serialization
`org.proofofhumanity.zk-holder-credential-input/1` already accepted by the holder circuit builder. Its semantic
commitment schema remains `org.proofofhumanity.zk-private-credential/1`. It contains the nonzero `uint32`
`statusId`, holder secret, independent blinding, normalized passport attributes and `issuedAtEpoch` in the frozen
field order.

`commitment` is the existing strict `org.proofofhumanity.zk-holder-credential-commitment/1` descriptor. The worker
must recompute Poseidon domain 1 over all 16 private-credential fields and require exact equality to the descriptor.
Issuer id, status id and issuance epoch must agree across the credential and commitment.

### Admitted issuer artifact

`issuerAuthentication` uses schema `org.proofofhumanity.zk-issuer-schnorr-artifact/1` and contains exactly:

```text
schema
scheme = schnorr-babyjubjub-poseidon-sha512-nonce/1
issuerKeyId
credentialCommitment
issuerPublicKey { x, y }
nonceCommitment { x, y }
responseScalar
```

Coordinates and the response are canonical decimal strings with ADR-0013's field/scalar bounds. The worker must
perform on-curve, nonzero and prime-subgroup checks, derive
`issuerKeyId = bytes32(Poseidon(domain=5,[A.x,A.y]))`, recompute the challenge from
`[R.x,R.y,A.x,A.y,C]`, and verify `sG + eA = R`. It must also require exact equality with the profile manifest's
allowlisted issuer, the commitment descriptor and issuance transcript.

The artifact deliberately omits the issuer secret, nonce scalar, nonce counter, SHA-512 digest, Poseidon challenge
and auxiliary randomness. They are unnecessary for verification; the secret and nonce material must never leave
the issuer, while storing derived challenge values would create a second representation which could disagree with
the circuit.

### Immutable issuance transcript

`issuanceTranscript` remains the strict, sanitized
`org.proofofhumanity.zk-holder-issuance-transcript/1`. It binds the commitment to the issuance chain, registry,
bridge, subject, verification authority, allocation transaction, status slot and epoch without retaining the raw
Self nullifier, registry duplicate key or bridge signature. It is historical evidence and is never rewritten by a
status refresh.

Its initial snapshot may differ from the current `statusWitness.snapshot` after a successful refresh. The current
witness must be for the same chain, registry and issuer, must cover the same status slot, and must not regress from
the transcript's initial publication.

### Replaceable private status witness

`statusWitness` uses schema `org.proofofhumanity.zk-packed-status-witness/1` and contains exactly:

```text
schema
scheme = poseidon-bn254-packed-status-depth24/1
issuerKeyId
statusId
snapshot {
  chainId, issuanceRegistry, snapshotId, root,
  activatedThroughStatusId, publishedAt
}
chunkLimbsLittleEndian[2]
siblingsBottomUp[24]
```

The root is one canonical nonzero BN254 field encoded as bytes32. Chunk limbs and siblings are canonical decimal
field values; each chunk limb is below `2^128`. The low eight `statusId` bits select the chunk bit and the high 24
bits select the Merkle path. Direction bits, the leaf hash and the path index are not stored: they are derived and
checked, avoiding redundant encodings.

The selected bit must be zero. The worker computes the domain-8 leaf, folds exactly 24 domain-3 siblings in
bottom-up order with directions derived from `statusId >> 8`, and requires the result to equal the snapshot root.
The snapshot must cover `statusId`, match an accepted non-retired on-chain publication and use its exact
`publishedAt`. A set bit means unallocated or revoked and cannot produce or refresh a presentation-ready vault.

Full snapshots are canonical sparse chunk lists. A missing chunk index means the 256-bit all-ones value, never
zero. The worker precomputes `default[0] = Poseidon(domain=8,[2^128-1,2^128-1])` and
`default[level+1] = Poseidon(domain=3,[default[level],default[level]])` through level 24. It parses strictly
increasing unique chunk indices below `2^24`, substitutes `default[level]` for every absent sibling, and combines
changed nodes left/right by the index bit at each level. The selected chunk and each of its 24 siblings come from
that single deterministic sparse map. Snapshot tail bits at and above `nextStatusId` must remain one. The computed
top node must equal both the snapshot root and the resolver-bound on-chain root.

## Decision 2 — Private refresh contract

The refresh is a one-job worker protocol, not an HTTP witness endpoint.

```text
public CDN / reconciler / chain
       │ same canonical full snapshot + attestations for every holder
       ▼
browser host ── encrypted vault + transferred unlock + public bundle ──► fresh worker
                                                                      decrypt
                                                                      validate issuer artifact
                                                                      derive private selector locally
                                                                      rebuild depth-24 path
                                                                      verify active bit + accepted root
browser host ◄──────────── replacement encrypted vault only ───────── re-encrypt
       │ atomic compare-and-swap against prior whole-vault digest
       ▼
local vault storage
```

The request is a structured-clone message, not JSON, with exactly these fields and types:

| Field | Exact type and source |
|---|---|
| `schema` | literal `org.proofofhumanity.zk-holder-private-status-refresh/1` |
| `version` | integer `1` |
| `jobId` | fresh 16-byte random value encoded as 22-character unpadded base64url; control-plane only |
| `priorVaultSha256` | 64 lowercase hex characters over RFC 8785/JCS UTF-8 canonical serialization of the **entire** input `PortableCredentialVault`; host-local CAS token which the worker recomputes before unlock |
| `vault` | one strictly parsed `PortableCredentialVault`; transferred/structured-cloned as authenticated ciphertext |
| `unlock` | `{ credentialId: string, prfOutput: ArrayBuffer }`; the PRF buffer is exactly 32 bytes and transferred, not cloned |
| `cohortBundles` | fixed-order array described below containing public resolution, snapshot and trust bytes for **every** worker-admitted chain/registry/issuer cohort; 1–32 entries, never one selected for a holder |

The worker binary, not the request, contains the allowed production profile/parameter digest, the reviewed
reconciler configuration hash and the allowed chain-resolver configuration. Host-supplied profile manifests,
issuer allowlists, reconciler keys, thresholds or RPC URLs are data, never trust roots.

Each `cohortBundles` entry has exactly `{ resolution, snapshotBytes, attestationBytes }`.
`snapshotBytes` is a transferred `ArrayBuffer` containing the canonical UTF-8 full sparse snapshot whose SHA-256
equals `resolution.snapshotContentSha256`. `attestationBytes` is a transferred `ArrayBuffer` containing the
canonical trust bundle defined below. The host must provide exactly the worker-bundled sorted cohort set; missing,
extra, duplicate or reordered entries reject before unlock. This avoids decrypting to learn an issuer and then
making an issuer-dependent network request. If the admitted cohort set grows beyond V1's bounds, a new padded or
oblivious routing version is required.

For every admitted cohort, the host resolves a refresh target in this order, entirely before vault unlock:

1. using the locally reviewed finalized-RPC quorum, resolve one exact immutable on-chain tuple
   `{ chainId, issuanceRegistry, registryRuntimeCodehash, issuerKeyId, issuerActive, snapshotId, root,
   activatedThroughStatusId, publishedAt, revoked, accepted, observationBlockNumber, observationBlockHash }` at
   one finalized block;
2. require `issuerActive = true`, `revoked = false`, `accepted = true`, a nonzero `uint32 snapshotId`, a canonical BN254 root, a `uint32` allocation
   watermark and `0 < publishedAt <= 4294967295` even though the registry stores `uint64` (V1 signal 17 is
   `uint32`);
3. verify the existing EIP-712 packed-status attestations under the worker-pinned reconciler set; they bind the
   Keccak-256 canonical `snapshotHash`, source block, `nextStatusId` and root under the chain/registry domain;
4. require the resolver quorum to bind that `snapshotHash` to the exact on-chain snapshot id, root, watermark,
   publication time, revoked flag and finalized observation; and
5. fetch immutable bytes by a separate lowercase 64-hex `snapshotContentSha256`, never through a
   credential-dependent or mutable `latestAcceptedSnapshot` resource, then recompute and require both Keccak-256
   `snapshotHash` and SHA-256 content digest over the same canonical bytes.

`resolution` is exactly the tuple above plus `snapshotHash`, `snapshotContentSha256`, `attestationSetSha256`,
`observationBlockTimestamp`, `validUntil`, `finalityRuleId` and the reviewed resolver/reconciler configuration
hashes. V1 hard limits aggregated across the whole request are 32 cohort bundles, 64 MiB snapshot bytes, 1,000,000
sorted non-default chunks, 128 KiB attestation bytes and 32 attestations of each kind; no individual bundle may
exceed an aggregate limit. The job also permits at most 64 JSON nesting levels, 256 MiB worker memory and 60
seconds wall-clock; the existing 256 KiB
vault-plaintext limit also applies. Both host and worker enforce these constants before unlock, and no request
field may raise them. The same cohort set and content-addressed bytes are fetched for every holder using that
worker build. The host must finish all network retrieval before transferring the unlock. The worker has no network
capability after decryption and the refresh protocol emits no progress events.

An ordinary RPC response is not an observation proof. V1 uses a worker-pinned threshold resolver configuration
whose hash binds chain id, registry address/runtime codehash, resolver EOA keys, threshold and finality-rule id.
`attestationBytes` is RFC 8785/JCS canonical UTF-8 JSON with schema
`org.proofofhumanity.zk-holder-status-refresh-trust-bundle/1`, integer version 1 and exactly two arrays. Each item
in both `snapshotAttestations` and `resolutionAttestations` has exactly `{ signer, signature }`, where `signer` is
one EIP-55 EOA and `signature` has the canonical encoding below; both arrays are sorted by lowercase signer with no
duplicates. Snapshot items are the compact signature-only form of the existing packed-status EIP-712 relation:
the worker reconstructs its typed-data digest from the single canonical `snapshotBytes` instead of duplicating a
potentially large snapshot inside each attestation. Resolution items sign the exact relation below.

Each resolver signs EIP-712 with domain
`{ name: "ProofOfHumanityStatusResolution", version: "1", chainId, verifyingContract: issuanceRegistry }` and
primary type `StatusResolution` in this exact order. `StatusResolution.configHash` is exactly
`resolution.resolverConfigHash`:

```text
bytes32 configHash
bytes32 registryRuntimeCodehash
bytes32 issuerKeyId
bool issuerActive
uint32 snapshotId
bytes32 snapshotHash
bytes32 root
uint32 activatedThroughStatusId
uint32 publishedAt
bool revoked
bool accepted
uint64 observationBlockNumber
bytes32 observationBlockHash
uint64 observationBlockTimestamp
uint64 validUntil
bytes32 finalityRuleId
```

All compact signatures are 65-byte `0x`-hex secp256k1 `r || s || v`, require low-`s`, `v` 27/28 and recovery to
the repeated nonzero EOA. The worker enforces unique locally allowlisted signers, both locally pinned thresholds,
exact tuple/config equality and `attestationSetSha256` over the canonical trust-bundle bytes; duplicate, unknown,
unsorted or mixed-tuple signatures reject. It also requires `publishedAt <= observationBlockTimestamp`,
`observationBlockTimestamp <= workerNow + 120`, `observationBlockTimestamp <= validUntil`,
`validUntil - observationBlockTimestamp <= 900` and `workerNow <= validUntil`, with all times in Unix seconds.
The browser's trusted wall clock is therefore a refresh-freshness input; proof-time root policy remains the final
authorization boundary. Thus the offline worker trusts the reviewed resolver/reconciler quorums, not an
unauthenticated host or RPC. A future light-client/state-proof observation is a new version of this trust bundle.

The worker executes in this order:

1. validate the job shape, exact complete admitted cohort set, aggregate resource limits, profile artifacts, every
   snapshot, both attestation thresholds and every finalized resolution before vault decryption; an invalid decoy
   bundle rejects the whole job and cannot become a selected-issuer oracle;
2. unlock and strictly parse the V1 production payload, then zero the transferred unlock copy as far as the runtime
   permits;
3. recompute the credential commitment and issuer key id, verify the Schnorr signature and enforce every
   cross-object equality;
4. compare the public snapshot with the issuance domain and stored witness, rejecting cross-chain, cross-registry,
   cross-issuer, uncovered, retired, future, stale or equivocated data;
5. derive the private chunk index and bit from `statusId`, select the chunk from the full public snapshot, build
   the 24 siblings locally, require the bit to be active and recompute the exact accepted root;
6. replace only `statusWitness`, preserving every other payload byte semantically, and encrypt under the existing
   vault key with a fresh 96-bit AES-GCM IV; and
7. return one exact result union, release all references and terminate the worker.

The result schema is `org.proofofhumanity.zk-holder-private-status-refresh-result/1`, version 1, and repeats only
the job id. `updated` carries exactly `{ status: "updated", replacementVault }`; `unchanged` carries exactly
`{ status: "unchanged" }`; and `failed` carries exactly `{ status: "failed", code }`. There is no free-form message
or digest. The failure enum is exactly `INVALID_REQUEST`, `PROFILE_REJECTED`, `VAULT_REJECTED`,
`SNAPSHOT_REJECTED`, `CREDENTIAL_UNUSABLE`, `RESOURCE_LIMIT`, `CANCELLED`, `DEADLINE_EXCEEDED` or
`INTERNAL_ERROR`. Every failure which depends on decrypted issuer, slot, witness, rollback or activity data
collapses to `CREDENTIAL_UNUSABLE`; no progress, nested detail or arbitrary error text crosses the worker boundary.
Production UI may map these codes to fixed local copy; it may not log or telemeter them with a vault identifier.

The host atomically writes an `updated` result only if RFC 8785/JCS canonical serialization of the **entire**
persisted vault still hashes to its host-local `priorVaultSha256`. The digest is input-only, never returned,
persisted as a receipt or sent to telemetry. Whole-envelope CAS is required because passkey enrollment and recovery
can change `keySlots` without changing payload ciphertext. A concurrent passkey enrollment, recovery rewrap or
newer refresh wins the race; the losing refresh discards its output and may retry from the newest ciphertext.
Partial plaintext, a witness-only object and an in-place ciphertext mutation are forbidden outputs.

Every success, failure, cancellation, deadline or caught runtime error releases references and terminates the
worker; an uncaught worker crash yields no result and therefore no write. The storage commit is one durable
transaction over the complete serialized vault and its CAS revision. A crash before commit leaves the exact old
vault; a completed commit exposes the exact new vault; no recovery path may observe or promote a partial mixture.

### Rollback and equivocation rules

For one chain/registry/issuer, a replacement snapshot id must be strictly greater and its `publishedAt` must be
non-decreasing; distinct publications in one block may legitimately share `block.timestamp`. The same snapshot id
is accepted only as an idempotent `unchanged` result when root, watermark and publication time are all identical.
The same id with different data, a lower id or a lower publication time is equivocation/rollback and fails closed.
The current finalized on-chain resolution remains authoritative for refresh even if local ciphertext was restored
from backup. Local monotonic checks are defense in depth, not revocation: an old witness remains valid while a
policy still selects and governance still accepts its exact old root/time. Governance must retire/revoke old roots
according to policy; at proof time ADR-0011's exact policy root/time is authoritative.

### Privacy and observability requirements

Within holder persistence and refresh, passport attributes, holder secret, blinding, chunk limbs, path and issuer
signature may exist only in decrypted worker memory and encrypted vault plaintext. The commitment and `statusId`
are one-time public issuance-event facts, but their association with this holder/session/vault and every selector
derived from the status id must remain client-private. Neither may become a holder refresh selector or application
identifier. The issuer artifact traverses only the authenticated private issuance channel into worker memory
before first vault sealing. None of these values or associations may appear in URLs, query bodies, RPC parameters,
service-worker caches, application state, crash reports, logs, analytics, support bundles or persisted refresh
receipts.

The first-party browser origin/window which receives the WebAuthn PRF result is a V1 trust root. Transferring and
detaching a buffer limits accidental retention by an honest host; it cannot stop XSS, a compromised extension or
malicious first-party code from cloning the PRF before transfer and decrypting the vault. Runtime approval
therefore requires a content-addressed same-origin worker, no third-party scripts on credential routes, restrictive
CSP and Trusted Types, immediate PRF transfer/drop, and a decrypted worker with no network capability. This ADR
does not claim confidentiality from a hostile browser origin.

There is no V1 fallback to `GET /witness/:statusId`, `GET /chunk/:index`, a Bloom-filter membership query or any
other selector-bearing service. If distributing a full canonical sparse snapshot becomes impractical, a future
version may use globally broadcast unkeyed deltas or a separately reviewed PIR design. That requires a new ADR and
cannot be negotiated silently by a client.

User-visible failures use only the exact bounded result enum above; every decrypted issuer/status/rollback/activity
failure is `CREDENTIAL_UNUSABLE`. Error text must not echo a nested field or distinguish a private slot. Detailed
diagnostics are allowed only over synthetic fixtures in explicit development builds.

Encryption does not hide all metadata. Snapshot CDN and RPC/resolver providers can observe client IP, timing,
traffic size and the public chain/registry/issuer/root cohort, although never a holder/status selector. Downloads
must be unauthenticated, cookie-free, content-addressed, cacheable and free of per-holder URLs or cache keys;
clients should prefetch at coarse cohort-wide times independent of vault unlock where feasible. Local or E2EE
backup providers can correlate the stable vault id, RP id, passkey credential identifiers, key-slot count,
ciphertext length, payload schema/version and update timing. These are accepted V1 residuals, must never be joined
to analytics, and require a new padded/oblivious storage version if the product later promises resistance to
network or backup-provider correlation. V1 provides selector privacy, not network anonymity.

## Decision 3 — Frozen presentation ABI

This storage decision adds **zero** public inputs and changes no Solidity ABI, event, storage layout, circuit id,
status publication format or NFT data. Every presentation still emits exactly these 18 signals in order:

```text
0  layoutVersion
1  circuitIdHi
2  circuitIdLo
3  issuerKeyIdHi
4  issuerKeyIdLo
5  activeRootHi
6  activeRootLo
7  policyHashHi
8  policyHashLo
9  presentationBindingHashHi
10 presentationBindingHashLo
11 nullifierScopeHashHi
12 nullifierScopeHashLo
13 scopedNullifier
14 subject
15 result
16 credentialEpoch
17 statusEpoch
```

The accepted witness root supplies signals 5–6 and its exact `publishedAt` supplies signal 17. Every V1 target
admission must prove that registry `publishedAt` is in `1..=0xffffffff` and the destination dynamic-policy
`currentStatusPublishedAt` equals it exactly; truncation, remapping or a second clock is forbidden. Issuer id and
credential epoch come from the issuer-authenticated credential. Commitment and status id are public issuance
facts but remain absent from presentation signals; issuer points/signature, chunk, path and attributes are private
circuit inputs. Any need for another public value is a new versioned circuit and additive interface migration, not
a payload patch.

## Decision 4 — Migration and reissuance

The synthetic/reference vault is not migratable in place. It lacks the issuer artifact and was explicitly sealed
as non-presentable under a different schema. Appending a signature or relabeling its schema cannot establish that
the production issuer saw and authenticated its original commitment. Because reference payloads were never
authorized for production allocation, a holder may repeat passport verification and receive a first production
credential. If an experimental registry already consumed that passport's duplicate key, a client must not bypass
the registry; that environment needs the same supersession work as an allocated production credential.

The current `ZkIdentityIssuanceRegistry` permanently consumes the registry-scoped duplicate key and exposes no
credential-supersession transition. Consequently this ADR does **not** authorize reissuance of any already
allocated credential. Issuer rotation, attribute correction and cryptographic migration are explicitly blocked
until a separate ADR threat-models and ratifies an additive registry supersession mechanism.

| Change | Operation | Reissuance required? | Authorized now? |
|---|---|---:|---:|
| New accepted root for the same chain/registry/issuer/profile | Private witness refresh; replace snapshot, chunk and 24 siblings only | No | **Yes** |
| Add/remove a passkey, recover, rotate vault key or re-encrypt | Rewrap/reseal the unchanged production payload | No | **Yes** |
| Unsigned pre-allocation slot/epoch race | Discard candidate, recommit to the newly observed slot/epoch and repeat passport binding | No; restart initial issuance | **Yes** |
| Never-production-allocated reference/candidate payload | Repeat passport verification and perform first production issuance | Yes | **Yes, only with an unused duplicate key** |
| Issuer key rotation or retirement of an allocated credential | Future registry supersession and new authenticated credential | Yes | **No — blocked** |
| Allocated status id or issuance epoch change | Future registry supersession; never rewrite the signed commitment | Yes | **No — blocked** |
| Passport attributes, expiry, document or assurance correction after allocation | Future registry supersession and new issuer authentication | Yes | **No — blocked** |
| Commitment, Schnorr, packed-status or private payload schema change after allocation | Future versioned profile plus registry supersession | Yes | **No — blocked** |
| Public-signal meaning/order/count change | Future layout/circuit plus registry supersession; never reinterpret V1 | Yes | **No — blocked** |

The future supersession design must, at minimum:

1. preserve the permanently consumed duplicate key and never reveal, free or reuse it;
2. prove continuity of the old `holderSecret` into the new commitment, or an equivalent cryptographic continuity
   relation which guarantees the same scoped nullifier for every overlapping V1 scope, without revealing the
   secret or creating a global presentation identifier;
3. allocate a fresh monotonically increasing status slot and epoch while making the old slot permanently
   non-reusable;
4. prevent any accepted-policy window in which both credential lineages can produce different scoped nullifiers;
5. revoke/retire every old active snapshot/issuer path before migration is considered complete; and
6. define crash-safe recovery which retains the old encrypted vault until the new ciphertext and transition
   evidence are durable, without claiming make-before-break presentation availability.

For issuer compromise or a privacy incident, governance must be able to revoke/retire the old issuer and snapshots
first even though that creates a holder outage. Incident containment takes priority over continuity; replacement
remains blocked until the reviewed supersession mechanism exists.

Backup restore does not migrate schema. A restored V1 production payload may refresh its witness and rewrap its
key slots. A restored reference/unknown payload remains non-presentable and may enter first production issuance
only when its production duplicate key is unused.

## Rejected alternatives

- **Mutate the reference payload.** Rejected because it changes a deliberately unratified contract and cannot
  prove production issuer authentication of the old commitment.
- **Store only a bearer issuer signature outside the vault.** Rejected because it makes a stable credential
  artifact available to application state and backup/telemetry surfaces.
- **Fetch a path by private status id.** Rejected because the endpoint learns a stable selector and can correlate,
  censor or selectively equivocate to one holder.
- **Put the full public snapshot in every vault.** Rejected because it bloats backups and couples credential
  ciphertext rotation to global public data. The vault stores only the derived witness; the full snapshot is
  authenticated public refresh input.
- **Sign the current status root with the credential.** Rejected because every new root would require issuer
  reissuance. Credential authenticity and current status are independent authorities and lifecycles.
- **Expose commitment/status id as new signals.** Rejected because it breaks the frozen ABI and creates a durable
  cross-presentation identifier.

## Ratification and implementation gates

The contract vector selects only fields from the ADR-0013 synthetic reserved-country reference, removes all
issuer secret/nonce material, carries exactly 24 siblings and independently pins the frozen 18-signal names. Its
test verifies the existing issuance transcript, issuer/status cross-bindings, active bit, parameter digest and
forbidden-key set. It is an interoperability and privacy-shape fixture, not a real credential or production key.

Internal security, privacy and reliability reviews approve this decision for implementation with no open
Critical/High findings. That approval is limited to the contract and data flow in this ADR. Runtime implementation
must still add strict parsers, circuit-native cryptographic verification, worker isolation tests, zeroization/lifetime
tests, atomic storage tests, restore/recovery drills and adversarial browser tests, then pass QA, reliability,
security and independent production audits. Until those gates and a `production-approved` circuit manifest are
green, product code must reject this schema for live persistence and presentation.

The required `v2-vault-contract` CI workflow watches every fixture and holder-runtime source consumed by the
contract test. It also pins the payload profile and reference circuit to the holder Worker constants and asserts
that the current browser engine fails closed for this production schema. Payload, issuer-authentication,
status-witness, refresh-envelope, migration-rule, frozen-signal or holder-boundary drift must therefore pass the
focused `pnpm test:v2-vault-contract` gate before merge.

The SDK now implements the strict payload parser, the exact one-job all-cohort Worker/client protocol, pre-decrypt
snapshot and threshold-attestation validation, transferred PRF lifetime, bounded result codes, fresh-IV payload
resealing and a whole-envelope atomic-CAS storage interface. The focused `pnpm test:v2-holder-refresh` suite uses
the contract vector and real EIP-712 recovery to exercise two complete cohorts, invalid-decoy rejection before
decrypt, resource bounds, unchanged/equivocation behavior, zeroization, cancellation and concurrent key-slot
races. A content-addressed Rust/WASM candidate now implements the circuit-native Poseidon credential/root/path
relations and Baby-Jubjub on-curve, nonzero, prime-subgroup, key-id and Schnorr checks behind that exact engine
interface. It is built from the isolated `tools/v2-holder-refresh-engine` crate so holder packaging cannot mutate
the frozen sanctions-ceremony source manifest. Its same-origin Worker package hash-checks the WASM before use,
reports real linear memory and
irreversibly masks ordinary fetch/socket/import capabilities before decrypt. Real WASM tests cover the ratified
vector, signature mutation, the order-two subgroup point, sparse-path/root reconstruction, resource limits and
cancellation. Both the engine's compile-time independent-audit bit and the packaged Worker's production policy bit
remain false; the generic disabled engine and browser prover also continue to reject production. Independent
cryptographic/browser reproducibility audits plus real Chromium, mobile, persistence and recovery evidence remain
mandatory before admission.

## Consequences

The holder lane now has one exact target and can implement without inventing a signature or witness envelope. Root
refresh is cheap for credentials and does not require passport re-verification. The privacy cost is a larger
broadcast snapshot download and local tree work, chosen deliberately to prevent a witness provider from learning
holder selectors. Issuer rotation and cryptographic upgrades are explicitly blocked until a separately ratified
registry supersession design preserves duplicate-key and scoped-nullifier continuity.
