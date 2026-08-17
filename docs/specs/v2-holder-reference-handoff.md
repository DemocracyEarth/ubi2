# V2 holder reference handoff and encrypted-vault boundary

- **Status:** implemented for synthetic/reference integration; live persistence remains blocked by ADR-0012
- **SDK:** [`zk-holder-reference-handoff.ts`](../../packages/sdk/src/zk-holder-reference-handoff.ts)
- **Credential/transcript parent:**
  [`v2-holder-credential-commitment.md`](v2-holder-credential-commitment.md)
- **Reference proving boundary:**
  [`v2-holder-reference-prover-worker.md`](v2-holder-reference-prover-worker.md)
- **Cross-lane boundary:** [`ADR-0012`](adr/0012-v2-cross-lane-interface-freeze.md)

## Outcome and non-goals

This slice joins the circuit-native holder commitment, sanitized live issuance transcript and encrypted
credential vault without exposing passport claims to application state. A dedicated worker can now:

1. accept a synthetic normalized passport-claim shape using only ISO user-assigned country codes;
2. generate an independent holder secret and credential blinding from Web Crypto;
3. call the trusted Rust/WASM commitment export with strict temporary JSON;
4. retain one private credential in an expiring in-memory session;
5. bind the exact validated issuance transcript; and
6. return only an AES-256-GCM vault protected by a WebAuthn-PRF/HKDF key slot.

The stored payload identifies itself as `reference-only-unratified` and has the literal field
`presentationReady: false`. It exists to validate the private handoff with synthetic data. It is not the live
product persistence path, a production credential schema or a presentation authorization. No WebAuthn UI,
IndexedDB wiring, recovery, backup or production proving circuit is introduced.

ADR-0012 remains controlling: no live passport credential may be issued or persisted until the circuit/verifier
lane publishes the selected commitment, issuer-authentication and status parameter profile and the integration
lead ratifies it.

## Reference state machine

```text
synthetic claims
    │ prepare (inside dedicated worker)
    ▼
CSPRNG holderSecret + credentialBlinding
    │ strict temporary JSON → trusted Rust/WASM builder
    ▼
sanitized commitment + random local session id
    │ exact validated allocation/snapshot transcript
    ▼
one-shot seal → authenticated encrypted vault

abort / expiry / destroy ────────────────► references dropped; worker should terminate
```

`ZkHolderReferenceHandoff` permits one pending session. The default lifetime is five minutes and the configured
maximum is ten minutes, matching the upper bound of the original authorization window. A session id is a random
128-bit base64url value used only inside the local worker protocol. It is not written to the vault, chain,
transcript or proof and must not be used for analytics.

A successful seal consumes the session before asynchronous encryption. A commitment/transcript binding failure
also consumes it, so a retry must generate fresh holder material and a fresh commitment. `abort()` removes one
session; `destroy()` removes every retained reference and invalidates an in-flight preparation. Because JavaScript
strings cannot be deterministically overwritten, callers must terminate the dedicated worker after seal, abort or
failure.

## Holder-material generation

Both private scalars are sampled independently from the platform Web Crypto CSPRNG. Each attempt interprets 32
random bytes as an unsigned big-endian integer and accepts only values in the interval
`1 <= value < BN254_SCALAR_FIELD`. It does not reduce modulo the field, which would introduce bias. Mutable random
byte buffers are overwritten after conversion, and equal secret/blinding samples are rejected.

The handoff accepts exactly these verified fields:

| Field | Canonical rule |
|---|---|
| `issuerKeyId` | nonzero bytes32, lowercase on the private handoff |
| `statusId` | nonzero `uint32` packed-status slot |
| `dateOfBirth`, `expiryDate` | exact valid `YYYY-MM-DD`; expiry later than birth |
| `nationality`, `issuingState` | trimmed and ASCII-uppercased to exactly three letters |
| `documentClass` | `epassport` |
| `assurance` | `passive-auth` or `chip-auth` |
| `issuedAtEpoch` | `uint32` |

Unknown input fields fail closed. The generated private fields are canonical nonzero decimal strings in the exact
`org.proofofhumanity.zk-holder-credential-input/1` JSON expected by the Rust/WASM reference builder. The JSON is
released after the builder call and never returned. Builder failures are replaced with a fixed non-sensitive
error so a lower layer cannot echo a claim through this API.

Both country fields must additionally be in the ISO user-assigned `XAA`–`XZZ` range. This is a runtime gate, not
just a fixture convention: the reference API cannot seal a real-country credential even if product code calls it
accidentally.

The builder is a security boundary: production integration must provide the reviewed in-worker circuit-native
export, not a remote callback or application-controlled hash function. Its sanitized descriptor is parsed with
the existing exact-key validator and must repeat the private input's issuer id, slot and epoch.

## Encrypted reference payload

The reference payload schema is:

```text
org.proofofhumanity.zk-holder-reference-vault-payload/1
```

It contains:

- the exact canonical private credential, including holder secret and blinding;
- the circuit-native commitment descriptor; and
- the sanitized allocation or snapshot-covered issuance transcript.

Before encryption and after every unlock, the SDK strictly validates all keys and values, reconstructs the exact
16-field credential preimage, and requires issuer id, status slot, issuance epoch and commitment descriptor to
match the transcript. Vault AEAD authenticates this relation at rest. The parser deliberately does not claim it
can recompute a selected production commitment: the trusted builder established that relation before sealing,
and the production profile remains unratified.

The vault envelope reveals only its generic format/version, random vault id, reference payload schema, relying
party id, random AEAD metadata and enrolled WebAuthn credential ids/key slots. It reveals no passport claim,
holder secret, blinding, private status slot, transcript hash or subject.

## Public versus private

| Field | Handoff/storage location | Public visibility |
|---|---|---|
| passport claims, holder secret, blinding | temporary worker memory; encrypted vault payload | never public |
| private status slot, transcript and transcript hash | temporary worker memory; encrypted vault payload | never an application identifier |
| local session id and expiry | temporary worker control state | never persisted or transmitted |
| commitment, issuer id, slot and epoch | sanitized preparation and issuance transaction/transcript | commitment/slot are issuance-public; commitment and slot remain absent from presentations |
| active status root | sanitized transcript when covered; existing presentation signal | public under existing governance semantics |
| vault id, RP id and passkey credential id | encrypted-vault envelope metadata | device/storage metadata only; never on chain or in proofs |
| scoped nullifier | not created by this slice | remains consumer/context/policy scoped in signal 13 |

The NFT/on-chain credential remains only an ownership, issuer-authorization, validity and revocation anchor. This
slice adds no NFT attribute, credential ciphertext or linkable presentation field.

## Compatibility and shared interfaces

- The 18 public signals are unchanged.
- No Solidity ABI, event, storage layout, circuit id, verifier or issuer-authentication format changes.
- Packed-status depth, bit convention, root and snapshot formats are unchanged.
- The candidate Poseidon commitment scheme and existing transcript remain explicitly unratified.
- The reference vault payload is SDK-local test scaffolding, not a frozen cross-lane or production storage format.

## NEEDS-INTEGRATION-DECISION

The circuit/verifier lane must publish a selected, versioned manifest covering the credential commitment
parameters, issuer-authentication envelope, status hash/profile and deterministic cross-language vectors. The
integration lead must then decide whether the selected scheme can migrate this reference payload or requires a
new production payload and reissuance. Until that decision merges, product code must not route live enrollment
claims into `sealReferenceVault` or treat its decrypted payload as prover-ready.

The separate slot/epoch race alternatives in the parent holder specification also remain unresolved. This slice
does not reinterpret refreshed transitional authorizations.

## Deterministic and adversarial evidence

The handoff consumes the existing pinned synthetic `XAA`/`XAB` 16-field commitment and issuance-transcript
contracts. Its SDK test performs a complete synthetic verified-claims → commitment → signed authorization →
allocation/snapshot transcript → encrypted vault → authenticated unlock flow. It asserts canonical country
normalization, scalar ranges and independence, one-session capacity, one-shot sealing, expiration, teardown,
wrong-passkey rejection, transcript mismatch rejection, payload tamper rejection, unknown-field rejection and
non-sensitive builder errors. Serialized preparation and vault envelopes are checked for private field names and
synthetic claim values.

The follow-on reference Worker control plane now pins one-job isolation, monotonic progress, cancellation,
deadlines, WASM-memory ceilings, exact 18-signal equality and sanitized failures without accepting a credential
witness or returning proof bytes. It remains non-presentable until a ratified profile supplies a new
profile-specific engine and proof path.
