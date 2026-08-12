# 10 — EVM ZK Identity v2: reusable private passport credential

- **Status:** proposed; foundation implementation started
- **Owner:** architect → cryptography engineer → protocol engineer → interface engineer → security auditor
- **Decision:** [ADR-0010](adr/0010-direct-v2-portable-zk-credential.md)
- **Builds on:** [ADR-0009](adr/0009-predicate-v2-and-final-onchain-surface.md),
  [`PredicateVerifier.sol`](../../contracts/src/PredicateVerifier.sol), and the M6 passport verifier

## Goal

Scan a compatible e-passport once, receive a private anonymous credential, and then create unlimited
consumer-bound ZK presentations on the holder's device. A presentation reveals only whether a declared
policy passed. It does not reveal the passport, exact date of birth, nationality, or a stable global
identifier.

The credential is portable across EVMs and devices. It is **not** stored in the NFT and is not tied to one
physical authenticator. A random vault key encrypts it; one or more passkeys wrap that vault key. The public
Proof-of-Humanity NFT remains an optional uniqueness/freshness anchor and contains no private attributes.

v1 remains available as a fallback while v2 is built and audited. The v1.5 on-demand/rescan product release
is deferred; its Self/Groth16 work may still be reused as issuance and verifier infrastructure.

## What a passport can support

An e-passport's machine-readable data and chip can attest document data such as date of birth, nationality,
issuing state, document type and expiry. The chip also carries a signed portrait and may support stronger
chip-authentication modes. This allows more useful predicates than `age>=18` and `nationality=ARG`.

| Predicate family | Example policy | v2 treatment |
|---|---|---|
| Document authenticity | `document-authentic` | Prove a trusted issuer signed the passport data and the document type is supported. |
| Human uniqueness | `one-human-per:proposal-42` | Emit a scoped nullifier; never expose the passport nullifier. |
| Age threshold/range | `age>=21`, `18<=age<65` | Prove arithmetic over private date of birth and a public reference date. |
| Nationality set | `nationality-in:EU`, `nationality-not-in:blocked-set-v4` | Prove membership/non-membership against a versioned public country-set root. |
| Issuing state | `issuer-in:trusted-set-v2` | Keep distinct from nationality; prove equality or set membership. |
| Document validity | `passport-valid`, `valid-for>=180-days` | Compare private expiry to a verifier-approved reference epoch. |
| Assurance class | `assurance>=epassport-passive-auth` | Prove which authenticated document/chip checks were completed. |
| Credential freshness | `issued-within:365-days` | Bind issuance epoch and an accepted active-credential root. |
| Stable within one scope | `same-human-in:community-7` | Derive a scope-specific pseudonym without a cross-context identifier. |
| Dynamic status | `sanctions-clear@2026-08-11` | Combine a short-lived status credential; never freeze a mutable list result into the long-lived credential. |
| Private field match | `name-commitment=application-field` | Optional, explicit-consent equality proof; do not disclose the field itself. |

### Facts that must not be implied

- Nationality does not prove current residence, tax residence, a visa, or a right to work.
- A chip portrait does not prove the presenter is live or matches the portrait. Liveness and face matching
  require a separate, consented credential and threat model.
- A passport does not prove income, profession, education, address, or criminal history.
- Sanctions status is external and time-varying. It needs short validity, list-version binding, and refresh.
- Name, exact birth date, passport number, portrait, and sex/gender are excluded from the default credential.
  A use case that needs one must justify data minimization and add an explicit schema/policy version.

## Privacy boundary

### Public

- proof-system and circuit version;
- issuer/credential-registry version and accepted active-root epoch;
- policy hash and Boolean result;
- chain id, verifier, consumer, context and wallet/smart-account challenge;
- scope-specific presentation nullifier or pseudonym;
- coarse proof epoch.

### Private witness

- holder secret and credential blinding;
- credential attributes needed by the selected circuit;
- issuer signature over the credential commitment;
- active-credential membership path;
- passport/issuance linkage material;
- passkey-derived vault-unlock material, which is never a circuit input or sent to a server.

The public `policyHash` commits to the complete canonical policy, including country-set root and status-list
version. A verifier must not accept a proof for a looser or differently versioned policy.

## Architecture

```text
one-time issuance
passport NFC -> passport/Self proof -> issuance verifier -> opaque credential signature
       |                                                      |
       +-- private attributes + holder secret ----------------+
                                      |
                                      v
                         AES-GCM encrypted credential vault
                         key slots: passkey A, passkey B, recovery

reusable presentation
passkey unlock -> local ZK prover -> PredicateVerifier.consumeWithProof -> consumer
                                     only policy/result/bindings/nullifier are public
```

### 1. Issuance

The holder generates `holderSecret` and an attribute commitment locally. The preferred target is a passport
issuance circuit that proves chip authenticity and binds the private passport attributes to that commitment;
the issuer sees only the commitment, document/nullifier status needed to prevent duplicate issuance, and
assurance metadata. It signs the commitment with a SNARK-friendly credential key.

The first testnet bridge may use Self to verify the passport and an issuer online **once** at issuance. Any
attribute disclosed to that bridge is visible to the issuer, so this is a transition architecture, not the
privacy end state. Presentations are still holder-generated and issuer-offline.

The long-lived base credential should contain only what enables approved predicate families:

- private date of birth, nationality, issuing state, expiry and document/assurance class;
- holder secret, issuer signature and credential status identifier/commitment;
- no passport number, portrait, name or sex/gender by default.

Dynamic checks such as sanctions use a separate short-lived status credential. Updating one must not require
reissuing the base passport credential.

### 2. Encrypted portable vault

The SDK foundation is [`credential-vault.ts`](../../packages/sdk/src/credential-vault.ts):

- random 256-bit data-encryption key per vault;
- AES-256-GCM payload encryption with schema, relying-party id and vault id as authenticated data;
- WebAuthn PRF output domain-separated through HKDF-SHA-256;
- AES-256-GCM key wrapping with one independently authenticated key slot per passkey;
- immutable multi-passkey enrollment, strict version/size validation, and fail-closed tamper detection;
- no plaintext local persistence and no server-held decryption key.

Passkey sync and ciphertext sync are separate. A platform provider may sync a passkey; the application must
also make the encrypted vault available on the second device (local transfer or end-to-end encrypted backup).
Where WebAuthn PRF is unavailable, the app must use a reviewed recovery key slot or keep v1/session-only mode;
it must not fall back to a password-derived key silently.

The current module is a cryptographic primitive, not authorization to persist production credentials. Before
product wiring it needs WebAuthn ceremony integration, schema validation, IndexedDB/E2EE backup, recovery,
logout/erasure, XSS controls, and an independent security review.

### 3. Presentation circuit

The holder proves all of the following in one circuit:

1. the issuer signature authenticates the private credential commitment;
2. the credential is active under an accepted status/registry root;
3. the private attributes satisfy the exact canonical policy;
4. the scoped nullifier is derived from the holder secret and `(consumer, context, policyHash)`;
5. the proof is bound to `chainId`, verifier, consumer, context, subject/account challenge and epoch.

The verifier outputs `result=true`; negative proofs are not useful for authorization and should be rejected by
default. A read-only verifier may expose false for diagnostics, but an authorization consumer must require true.

### 4. Proof system and EVM adapter

The initial target is a Groth16 proof over BN254 because the repository already operates that stack and EVMs
have pairing precompiles. This is a benchmark hypothesis, not a permanent lock-in. Stage 1 must compare prover
time/memory, circuit constraints, verifier bytecode, verification gas, setup/update risk and mobile/browser
support against at least one modern universal-setup alternative.

Inside the circuit, benchmark a SNARK-native issuer signature (for example Baby-Jubjub EdDSA/Poseidon) against
an active-credential Merkle-membership design. Do not introduce BBS+/BLS12-381 directly on EVM without measuring
the cost of its required curve operations or SNARK wrapper.

The generated verifier sits behind the existing forever-interface:

```solidity
IPredicateProver.verifyPredicate(proof, publicSignals, context)
    -> (subject, predicate, result, epoch)
```

`PredicateVerifier` continues to own freshness, consumer/subject binding and replay checks. Circuit versions
are additive prover contracts; an audited registry/multisig with a timelock controls which versions consumers
may accept. No proof-system upgrade may mutate the SBT or its holders.

### 5. Wallet and account binding

A presentation is bound to an EVM subject and a fresh challenge. EOAs use an EIP-712 wallet signature; smart
accounts use ERC-1271. A passkey-controlled smart account may own the NFT later, but vault encryption and wallet
authorization remain distinct domains. Losing one wallet must not reveal the credential, and compromising an
encrypted backup must not authorize the smart account.

## Threat model and required failures

- A stolen ciphertext without an enrolled passkey/recovery factor reveals no credential data.
- A passkey credential id alone, or a wrong PRF result, cannot unwrap the vault key.
- Changing vault binding, ciphertext, IV, key-slot metadata or wrapped key fails authentication.
- An issuer cannot create multiple active credentials for one passport outside the duplicate/nullifier policy.
- A holder cannot change attributes, policy parameters, status root, subject or context after proof generation.
- Two consumers cannot correlate presentations unless the holder deliberately reuses a public wallet or scope.
- A proof cannot be replayed to another chain, verifier, consumer, action or policy version.
- A stale/revoked credential or stale sanctions status fails closed.
- Compromise or rotation of an issuer/prover key has a documented containment and recovery path.
- XSS is in scope: decrypted material is short-lived, never logged, and proving runs in an isolated worker.

## Delivery roadmap

### Stage 0 — architecture and vault foundation (current)

- Ratify ADR-0010, this spec and the predicate matrix.
- Ship the versioned encrypted-vault SDK primitive and deterministic tamper/multi-passkey tests.
- Add SDK tests to CI. Do not wire persistent production storage yet.

**Implemented foundation (2026-08-12):** the encrypted multi-passkey vault, canonical policy schema,
deterministic EVM policy/presentation-binding hashes, SDK vectors, and the explicitly non-proof `/verify` policy
designer are implemented. The first Stage 1 compatibility slice also pins the private-credential ABI,
nullifier scope/preimage, and lossless public-signal layout across TypeScript, Solidity, and Rust. Ratification,
security review, and the final Stage 1 cryptographic decision remain open. A first isolated, reproducible
[desktop authentication spike](../../tools/v2-crypto-bench/README.md) now compares issuer signature, depth-32
active-registry membership, and both together; it is explicitly preliminary and does not ratify a circuit.

Pinned TypeScript vectors (`packages/sdk/src/zk-identity-policy.test.ts`):

| Vector | Hash |
|---|---|
| age `18<=age<65` at `2026-08-12` | `0x3f71ddd64fc1edef180756674529dd32b2c90f7288d2f0ced062e781a0cda3a2` |
| country-set root `eu-eea:2026-08` over fixture `ARG,DEU,NOR` | `0x8c534f5e9d271d455fc8a3f21a6e2faf3a2584dc8a1e1b6ade25c61de71df245` |
| nationality-in policy using that root | `0xace19152a22fb55223bb3931b2fa4a96b7df79bf75f5dcad2468d2c82dfda734` |
| presentation binding fixture (Base Sepolia) | `0xfcbaa318d3aba026a8827d332ec45ae24e9dbdd9ca6029b6fd3741b4e670e7a0` |

The country root above is a deliberately small parity fixture, not a production EU/EEA registry root.

### Stage 1 — cryptographic spike and pinned schemas

- Pin canonical credential, policy, public-signal and nullifier encodings with cross-language vectors.
- **Compatibility slice implemented:** policy and EVM presentation bindings are pinned in
  [`zk-identity-policy.ts`](../../packages/sdk/src/zk-identity-policy.ts). The private-credential ABI,
  scoped-nullifier preimage, and public-signal layout are pinned in
  [`zk-identity-encoding.ts`](../../packages/sdk/src/zk-identity-encoding.ts),
  [`ZkIdentityEncoding.sol`](../../contracts/src/ZkIdentityEncoding.sol), and
  [`v2_identity.rs`](../../crates/zkpoh/src/v2_identity.rs), with identical fixtures in all three languages.
- Benchmark signature/accumulator and proof-system candidates on desktop, mid-range mobile and EVM L1/L2.
- **Desktop authentication baseline implemented:** the isolated
  [`v2-crypto-bench`](../../tools/v2-crypto-bench/README.md) harness pins constraint counts, tests invalid
  signatures/paths fail closed, and generates/verifies a Groth16 proof for each signature, registry, and hybrid
  relation in CI. Mobile/browser, alternate hash/proof-system, EVM gas, and witness-update measurements remain.
- Produce a circuit threat model, constraint audit plan, setup/ceremony plan and version registry design.
- Exit: one decision ADR with measured results; no cryptographic choice based only on familiarity.

#### Pinned private credential ABI (version 1)

The private credential is ABI-encoded in this exact order:

```text
domain, version, issuerKeyId, statusId, holderSecret, credentialBlinding,
dateOfBirth, nationality, issuingState, expiryDate, documentClass,
assurance, issuedAtEpoch
```

Dates are `YYYYMMDD` `uint32` values; country codes are ISO alpha-3 `bytes3`; holder secret and blinding are
non-zero canonical BN254 scalar-field elements. The fixture's Keccak fingerprint exists only to detect
cross-language encoding drift. It is **not** the circuit credential commitment and must never be published as
a presentation identifier. The circuit-native commitment and issuer-authentication scheme remain Stage 1
benchmark decisions.

#### Pinned scoped-nullifier input (version 1)

The public scope hash commits to:

```text
domain, version, mode, chainId, verifier, consumer, context, policyHash
```

The ordered private circuit preimage is:

```text
nullifierDomainHi, nullifierDomainLo, version, holderSecret, scopeHashHi, scopeHashLo
```

`subject`, challenge, and epoch are deliberately absent. A holder must not gain another one-per-scope slot by
changing wallets, refreshing a challenge, or waiting for a new epoch. A measured SNARK-native hash consumes
this preimage; this slice does not pre-select Poseidon or another candidate.

#### Pinned public signals (version 1)

Every entry is a strict canonical BN254 scalar and the vector has exactly 18 entries:

| Index | Signal |
|---:|---|
| 0 | layout version |
| 1–2 | circuit id, high/low 128-bit limbs |
| 3–4 | issuer key id, high/low limbs |
| 5–6 | active credential root, high/low limbs |
| 7–8 | policy hash, high/low limbs |
| 9–10 | presentation binding hash, high/low limbs |
| 11–12 | nullifier scope hash, high/low limbs |
| 13 | scoped nullifier |
| 14 | EVM subject as a zero-extended `uint160` |
| 15 | Boolean result (`0` or `1`) |
| 16 | credential epoch (`uint32`) |
| 17 | dynamic-status epoch (`uint32`; `0` when unused) |

All `bytes32` values use two 128-bit limbs rather than modular reduction. This is lossless and prevents two
different EVM hashes from aliasing to the same circuit field. SDK, Solidity, and Rust decoders reject wide
limbs, zero identifiers, non-canonical fields, invalid subjects/results, and oversized epochs.

### Stage 2 — one-time issuance on testnet

- Build the Self issuance bridge, holder commitment and duplicate-issuance registry.
- Issue an age/nationality/expiry-capable credential once; issuer is not contacted for presentations.
- Define base-credential and short-lived dynamic-status lifecycles, rotation and revocation.
- Exit: second issuance for the same passport is rejected; issuer learns only the documented transition fields.

### Stage 3 — local prover and passkey product

- WebAuthn PRF feature detection and user-verification ceremony; multiple passkeys and reviewed recovery.
- IndexedDB plus optional E2EE ciphertext backup; import/export, device-add, revoke-device and erase flows.
- Browser worker/WASM proving with progress, cancellation and memory limits.
- Exit: scan once, restart browser, prove offline, add a second device, and recover without passport rescan.

### Stage 4 — EVM verifier and developer SDK

- Generated verifier + `IPredicateProver` adapter + active-root/version registry.
- SDK policy builders and public-signal encoding for age, country sets, issuer sets, validity and uniqueness.
- Integration examples for read-only apps, stateful contracts, EOAs and ERC-1271 smart accounts.
- Exit: proof accepted on all target testnets; wrong chain/consumer/context/policy/root and replay all fail.

### Stage 5 — audit, ceremony and mainnet release

- Independent circuit/constraint audit, Solidity audit, browser/vault review and privacy review.
- Reproducible circuit artifacts and verifier bytecode; production setup/ceremony if required.
- Adversarial testnet, load/gas/prover telemetry with no private data, incident and key-rotation drills.
- Deploy L2s first, then Ethereum after the measured gas/operational gate; timelocked multisig governance.
- Exit: no open Critical/High, documented residual risks, verified source/bytecode and end-to-end release runbook.

## Definition of done

- A holder scans once and can later prove at least age threshold, country-set membership, document validity
  and one-per-context uniqueness without the passport or issuer online.
- Presentations for two consumers have no common credential identifier or nullifier.
- A developer integrates one read-only and one stateful EVM gate from the SDK documentation.
- The same encrypted credential is usable from two enrolled passkeys; loss/revocation/recovery are demonstrated.
- No exact DOB, nationality, name, passport number, portrait, global nullifier or credential plaintext appears
  in calldata, logs, contract storage, analytics, browser storage or server logs.
- Revocation and dynamic sanctions freshness are independently testable and fail closed.
- Target-chain gas and target-device proving budgets are met and recorded before mainnet values are promised.

## Open decisions for Stage 1

- Exact issuance privacy: temporary Self disclosure bridge versus a commitment-output/passport-native circuit.
- Credential authenticity: SNARK-native issuer signature, accumulator membership, or both.
- Revocation accumulator and witness-update mechanism.
- Proving stack after measurement; trusted-setup and verifier-version governance.
- Whether the public subject is an EOA, ERC-1271 account, or a scoped account key for each product flow.
- Recovery design when neither a synced passkey nor WebAuthn PRF is available.
