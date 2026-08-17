# ADR-0010 — Go directly to a portable, reusable ZK passport credential

- **Status:** proposed
- **Date:** 2026-08-11
- **Deciders:** product owner, architect, cryptography engineer and security auditor
- **Supersedes:** the product sequencing and “Why NOT go straight to full v2” conclusion in
  [ADR-0009](0009-predicate-v2-and-final-onchain-surface.md). ADR-0009's permanent on-chain verifier seam
  remains unchanged.
- **Companion spec:** [`10-evm-zk-identity-v2.md`](../10-evm-zk-identity-v2.md)

## Context

v1 proves Boolean passport predicates through an online issuer and keeps its private `HumanCredential` only
for a browser session. v1.5 proposed a trustless Self proof per presentation, but still requires the passport
or a short-lived Self session. The target experience is scan once and make many unlinkable proofs.

The already-deployed contract design does not force an intermediate product release. `ProofOfHumanity` stores
no attributes, and `PredicateVerifier` already delegates holder proofs through `IPredicateProver`. Therefore we
can keep v1 as a fallback, reuse useful v1.5 infrastructure, and direct new product development to v2 without
migrating the NFT or changing the forever-interface.

## Decision

1. **Make v2 the next predicate product milestone.** v1 stays operational until v2 is audited. v1.5 is not a
   separately launched user journey; its Self/Groth16 work is reusable infrastructure.
2. **Keep private attributes out of the NFT and chain state.** The NFT is an optional public uniqueness and
   freshness anchor, not a credential container or encryption key.
3. **Issue one portable anonymous credential.** A holder-side commitment contains the minimal passport facts,
   holder secret and credential status material. The issuer participates once, then is offline for proofs.
   The target issuance circuit hides attributes from the issuer; a Self disclosure bridge is explicitly a
   transitional testnet architecture.
4. **Encrypt the credential with a random vault key.** Passkeys authenticate the holder and, through WebAuthn
   PRF, wrap that key. The credential is tied to the vault/holder secret, not to one device or passkey.
   Multiple passkey and recovery key slots can unlock the same ciphertext.
5. **Generate consumer-bound ZK presentations locally.** The proof binds policy, chain, verifier, consumer,
   context, subject/account challenge, freshness/status root and a scope-specific nullifier.
6. **Use the existing EVM seam.** The first measured target is Groth16/BN254, but the proof system and in-circuit
   credential authentication are not pinned until Stage 1 benchmarks. Each circuit version is a replaceable
   prover behind `IPredicateProver`; the SBT is unchanged.
7. **Separate long-lived passport facts from dynamic status.** Sanctions and similar mutable decisions use
   short-lived, versioned status credentials and cannot inherit the base credential's validity period. Proposed
   [ADR-0011](0011-dynamic-status-freshness.md) pins the snapshot publication-time and maximum-age boundary.
8. **Do not enable production persistence in the first slice.** Ship and test the vault primitive first;
   WebAuthn ceremony, recovery, isolated proving, E2EE backup, schema validation and security review gate UI
   integration.

## Consequences

### Positive

- One passport interaction supports many age, country-set, expiry and uniqueness policies.
- The issuer is offline for presentations and does not become a record of every consumer interaction.
- A synced or newly enrolled passkey can unlock the same encrypted credential on another device.
- Consumers keep the existing verifier address and integrate a proof-system-neutral interface.
- Sensitive passport facts remain private even if the encrypted backup or NFT is public.

### Costs and risks

- This is a new circuit, credential lifecycle, local prover and recovery system. Mainnet requires independent
  circuit, contract and browser/vault audits.
- Passkey sync is provider-dependent, WebAuthn PRF is not universal, and syncing a passkey does not sync the
  encrypted credential. The product must make these states visible and provide reviewed recovery.
- Credential revocation and dynamic status require public roots and witness-update mechanics.
- Groth16 may minimize EVM verification cost but introduces circuit-specific setup/versioning. The benchmark
  and ceremony decision cannot be skipped.
- A Self issuance bridge can expose requested attributes to the issuer. Product copy and telemetry must not
  claim issuer-blind issuance until a commitment-output/passport-native circuit is live.

## Rejected alternatives

- **Put attributes or encrypted attributes in NFT metadata.** Public ciphertext creates permanent correlation,
  makes rotation/recovery harder and lets future cryptanalysis target an immutable record.
- **Use the NFT itself as a passkey.** An NFT cannot protect a decryption secret or demonstrate user presence.
- **Bind the credential to one device authenticator.** Device loss would force passport re-enrollment and breaks
  the portability goal.
- **Rely only on passkey-provider sync.** It does not guarantee ciphertext sync, independent recovery or support
  for single-device credentials.
- **Persist v1 `HumanCredential` plaintext in localStorage/IndexedDB.** This expands an issuer-trusted demo
  credential into a durable XSS target without the v2 privacy or recovery model.
- **Put sanctions-clear in the long-lived passport credential.** Sanctions lists and identity matches change;
  a stale pass would create a false security claim.

## Ratification gate

This ADR becomes accepted only after Stage 1 records measured proof-system/credential-authentication results
and the security owner approves the threat model. Starting the vault primitive does not pre-decide the circuit.

**Implementation note (2026-08-16):** the holder lane now pins the versioned private-credential Poseidon
commitment and sanitized issuance transcript in
[`v2-holder-credential-commitment.md`](../v2-holder-credential-commitment.md). This does not ratify the production
issuer-signature envelope or proof system. It also exposes a pre-existing integration conflict: a commitment that
binds `statusId`/`issuedAtEpoch` cannot survive the transitional bridge's grant-preserving refresh of those fields.
No shared ABI changed; the alternatives and consequences are recorded as `NEEDS-INTEGRATION-DECISION`.
