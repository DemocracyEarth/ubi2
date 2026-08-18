# V2 holder profile Worker/WASM proving boundary

- **Status:** profile-specific boundary implemented; executable fixture remains synthetic until production admission
- **Profile:** `org.proofofhumanity.v2-crypto.groth16-bn254-poseidon/1`
- **SDK control plane:** [`zk-holder-profile-prover-worker.ts`](../../packages/sdk/src/zk-holder-profile-prover-worker.ts)
- **Browser/WASM adapter:** [`zk-holder-profile-browser-runtime.ts`](../../packages/sdk/src/zk-holder-profile-browser-runtime.ts)
- **Synthetic artifact manifest:** [`holder-profile-browser-artifacts-v1.json`](../../fixtures/v2-production-crypto/holder-profile-browser-artifacts-v1.json)
- **Parent decisions:** [ADR-0012](adr/0012-v2-cross-lane-interface-freeze.md) and
  [ADR-0013](adr/0013-v2-production-cryptographic-profile.md)

## Outcome and admission boundary

This is the dedicated profile-specific successor to the permanently reference-only Worker. It fixes the profile,
Groth16 proof encoding and frozen V1 public-input layout while keeping vault plaintext outside the browser host.
It has two deliberately unequal modes:

- `production` requires a strictly parsed `production-approved` per-circuit manifest, an exactly linked admission
  record, a Worker-bundled/local admission allowlist decision and every content-addressed circuit artifact listed
  by that manifest. A host-provided manifest/record is never sufficient by itself. Candidate, missing, research,
  non-allowlisted or hash-mismatched evidence rejects before vault decryption or proving.
- `synthetic` accepts only `synthetic:production-profile-sanctions-v1`, the ratified sanctions circuit ID and the
  checked-in content-addressed WASM. It consumes only the exact XAA/XAB test credential, uses deterministic public
  toxic waste, returns `presentationReady: false` and can never be relabeled as production.

There is no production-approved manifest or ceremony artifact in the repository at this revision. Therefore the
production gate is implemented and adversarially tested, but the only runnable engine is the explicit synthetic
fixture. This does not bypass ADR-0012 or promote the old research circuit ID.

## Private ingress and one-shot execution

```text
browser host                                      disposable module Worker
------------                                      ------------------------
encrypted PortableCredentialVault ──────────────► validate ciphertext envelope
copied PRF result (transferred, not cloned) ─────► unlock AES-GCM vault; zero PRF copy
public artifact bytes + pinned SHA-256 ──────────► hash before decrypt/prove
frozen expected 18 signals ─────────────────────► validate circuit + issuer bindings
                                      plaintext  parse exact private vault schema
                                                 build witness in WASM memory
                                                 Groth16 prove + local verify
abort/deadline ─────────────────────────────────► hard Worker termination
proof uint256[8] + 18 signals + receipt ◄──────── discard witness/key/plaintext references
```

The host-side client makes private copies of the PRF result and artifact buffers, transfers their backing buffers
to the Worker and never sends decrypted fields. The Worker verifies all content digests before unlock, decrypts
with Web Crypto, invokes the engine's strict private-payload parser and passes the credential to WASM. It zeroizes
the transferred PRF view and all transferred artifact views during teardown; a fresh Worker is required per run.
JavaScript strings cannot be reliably overwritten, so termination is the final lifetime boundary.

The current production credential envelope remains intentionally undefined. ADR-0013 ratified issuer
authentication, but no admitted issuance envelope yet carries the issuer Schnorr artifact and refreshable private
status witness. The generic Worker-private engine seam owns that future parser. This PR does not reinterpret the
reference vault as a production format.

## Content-addressed artifact rules

Synthetic execution requires exactly one `wasmModule` whose bytes hash to:

```text
sha256:1a931e60b3bea49c709747906671ea74b60cd1a877d1a8d7bc962db1d6be009e
```

The committed WASM is generated with Rust 1.96.0, wasm-bindgen 0.2.125 and wasm-pack 0.15.0 in locked release mode.
The build script rejects byte drift. The fixture manifest records its exact byte count and categorically marks it
synthetic/non-presentable.

Production execution requires the exact eight artifact roles already frozen by
`org.proofofhumanity.zk-production-profile/1`: parameter manifest, circuit source, constraint system, compiler
lock, prover artifact, verifier artifact, verifier source and public-signal manifest. Roles must be unique; both
the supplied digest and the locally computed SHA-256 must equal the approved manifest. The Worker never downloads
manifest URLs, so mutable hosts cannot redirect private processing or cause Worker-side network access.

The generic engine seam must independently return `admitsProductionProfile: true` for the exact parsed manifest
and admission record. A production Worker is expected to compile an approved manifest-hash allowlist into its
content-addressed bundle (or verify an equivalently authenticated local admission source). The currently shipped
browser engine always returns false. This is necessary because the release gate's JSON record is public data, not
an authorization signature, and could otherwise be fabricated together with a self-authored manifest.

## Proof output and local verification

The WASM export `proveSyntheticHolderProfile` accepts only the normalized synthetic private credential JSON. It
constructs the ratified sanctions relation, uses the profile's credential commitment, Baby-Jubjub issuer
authentication, depth-24 packed status tree and profile circuit ID, then generates and locally verifies Groth16.
Only the proof and public inputs return to TypeScript; the proving and verification keys remain inside WASM.

The receipt encodes the proof as eight 32-byte EIP-197/Solidity words:

```text
[A.x, A.y, B.x_imaginary, B.x_real, B.y_imaginary, B.y_real, C.x, C.y]
```

It serializes the public vector as exactly eighteen 32-byte words. The Worker re-decodes the vector, requires its
circuit ID to match the selected profile, requires production issuer IDs to be approved by the manifest, requires
the engine's local verification result to be true and then emits `locallyVerified: true`. A false verification,
changed signal, malformed coordinate, wrong proof length or memory overrun yields only a bounded failure code.

## Public versus private

| Field or artifact | Visibility | Notes |
|---|---|---|
| circuit and issuer IDs, accepted status root/time | public signals | frozen positions 1–6 and 17 |
| policy, presentation and nullifier-scope bindings | public signals | frozen positions 7–12 |
| scoped nullifier, subject, Boolean result, credential epoch | public signals | frozen positions 13–16 |
| Groth16 proof | returned to host | randomized proof output; synthetic proof is non-presentable |
| profile/admission hashes and artifact SHA-256 values | receipt/Worker messages | public supply-chain metadata |
| encrypted vault and public key-slot metadata | host/Worker message | authenticated ciphertext only |
| PRF result | transferred host-to-Worker | secret unlock material; zeroized Worker copy, never returned |
| passport attributes, holder secret and blinding | Worker/WASM only | never included in progress, errors or receipt |
| credential commitment, issuer signature and status slot/path | Worker/WASM only during presentation | absent from all 18 presentation signals |
| NFT/on-chain credential | public anchor only | no attribute, ciphertext or linkable credential identifier added |

## Frozen shared interfaces

- Public-signal layout/version/count remains exactly V1/18.
- Groth16 output is the already-consumed `uint256[8]` EVM verifier shape.
- No Solidity ABI, registry/event/storage, NFT or packed-status publication format changes.
- No production credential/vault schema is introduced.
- The old reference-only Worker and receipt remain unchanged; callers must opt into this new schema and module.

## Remaining production blockers

The circuit/verifier and release lanes must publish a `production-approved` per-circuit manifest containing the
ceremony proving/verifying artifacts, audited constraint system and sources, compiler lock, representative device
evidence and deployed target evidence. The holder/integration lane must separately ratify an issuer-authenticated
production vault payload plus private status-witness acquisition/refresh. Only then can a production WASM loader
and engine parser replace the synthetic adapter without changing this Worker protocol or the 18-signal ABI.

## Deterministic and adversarial validation

SDK tests prove that the encrypted host envelope omits private credential fields, plaintext reaches only the
Worker-private engine, the caller-owned PRF/artifact buffers are not mutated, and a successful receipt contains an
exact proof plus eighteen signals. They reject a one-byte artifact mutation, digest substitution, candidate
profile, bad unlock, false local verification, signal drift, proof/report extensions and synthetic-to-production
relabeling. Rust release tests generate and locally verify the actual profile-specific Groth16 fixture and reject
a changed synthetic credential.
