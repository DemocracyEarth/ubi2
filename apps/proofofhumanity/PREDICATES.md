# Predicate integration guide

Proof of Humanity v1 lets a verified holder present one Boolean fact to one consumer without
putting the underlying age or nationality on-chain. The live path is **issuer-attested**:

1. Self verifies the selected passport facts on the holder's phone.
2. The issuer creates a signed private `HumanCredential` for the browser session.
3. The holder asks `/api/predicate` for one canonical descriptor.
4. The API confirms the credential signature and freshness, the subject's live soulbound token,
   the configured chain/verifier pair, and both on-chain issuer addresses.
5. `PredicateVerifier.check` validates a read-only artifact, or a consumer contract calls
   `consume` to validate and spend it atomically.

The consumer receives only the Boolean and its binding envelope. The v1 issuer sees the private
credential while evaluating it. Holder-side ZK is specified as a future prover implementation but
is not built or deployed; `PredicateVerifier.prover() == address(0)` disables that path.

The active v2 design is [`docs/specs/10-evm-zk-identity-v2.md`](../../docs/specs/10-evm-zk-identity-v2.md):
one encrypted private passport credential, passkey-protected and portable across enrolled devices, produces
reusable holder-side proofs. The vault SDK foundation is exported from `@ubi2/sdk`, but production persistence
is intentionally not wired until the WebAuthn ceremony, recovery, schema validation and security review land.

### v2 vault foundation (experimental)

The application first generates a PRF salt, passes its decoded 32 bytes to a user-verified WebAuthn
create/get ceremony as `extensions.prf.eval.first`, and reads `results.first`. The ceremony is intentionally
application-owned because RP origin, challenge, credential allowlist and user-verification policy are security
decisions:

```ts
import {
  addPasskeyKeySlot,
  createPasskeyProtectedCredentialVault,
  generatePasskeyPrfSalt,
  parseCredentialVault,
  unlockCredentialVault,
} from "@ubi2/sdk";

const prfSalt = generatePasskeyPrfSalt();
const { credentialId, prfOutput } = await yourVerifiedWebAuthnPrfCeremony(prfSalt);

const vault = await createPasskeyProtectedCredentialVault(
  validatedPrivateCredential,
  { schema: "org.proofofhumanity.passport.v2", rpId: "proofofhumanity.org" },
  { credentialId, prfSalt, prfOutput },
);

// Persist only JSON.stringify(vault). Treat deserialized data as untrusted.
const stored = parseCredentialVault(JSON.parse(await loadEncryptedVault()));
const plaintext = await unlockCredentialVault(stored, { credentialId, prfOutput });
const credential = validatePrivateCredentialSchema(plaintext);

// After authenticating the existing and new passkeys, both can wrap the same vault key.
const portable = await addPasskeyKeySlot(stored, existingUnlock, newPasskeyEnrollment);
```

Do not persist `prfOutput`, decrypted plaintext, or a raw vault key. Feature-detect WebAuthn PRF and make an
unsupported authenticator/recovery state explicit; never silently downgrade to a password-derived key.

### v2 canonical policies (experimental)

`@ubi2/sdk` also exports the version-1 semantic policy contract used by the `/verify` v2 designer:

- `normalizeZkIdentityPolicy` validates and pins age ranges, country-set membership/non-membership,
  document validity/authenticity, scoped uniqueness, dynamic sanctions status, and consented private matches;
- `zkIdentityPolicyHash` commits to the complete normalized policy with EVM ABI encoding;
- `countrySetCommitment` produces deterministic demo/registry commitments from sorted ISO alpha-3 members;
- `normalizeZkPresentationBinding` and `zkPresentationBindingHash` bind a policy to chain, verifier, consumer,
  subject, context, challenge, and epoch.

These helpers are real SDK inputs and deterministic hashes, but they are **not proofs**. Do not authorize from
them until an audited circuit and configured `IPredicateProver` authenticate the same policy and presentation
binding. Production country/status roots must come from allowlisted governed registries, not local demo lists.

## Install

The repository SDK exports the public ABI, types, descriptor helpers, EIP-712 digest recovery, and
read-only contract check:

```ts
import {
  checkPredicateArtifact,
  predicateContext,
  predicateDescriptor,
  predicateDescriptorHash,
  predicateVerifierAbi,
  recoverPredicateIssuer,
  type PredicateArtifact,
} from "@ubi2/sdk";
```

## Canonical descriptors

| Descriptor | Meaning |
|---|---|
| `age>=18` | the holder prepared and passed the 18+ threshold |
| `age>=21` | the holder prepared and passed the 21+ threshold |
| `nationality=ARG` | private nationality equals ISO 3166-1 alpha-3 `ARG` |
| `sanctions-clear` | mandatory Self sanctions screening passed |

Descriptors are case-sensitive and whitespace-free. Consumers compare the exact hash:

```ts
const required = predicateDescriptorHash("age>=18");
const context = predicateContext("community:season-1");
```

## Request shape

`POST /api/predicate` accepts:

```ts
{
  credential,       // private HumanCredential kept in the holder's browser session
  credentialSig,    // issuer signature over that credential
  predicate,        // canonical plaintext descriptor
  consumer,         // app address for check(), contract address for consume()
  context,          // bytes32 chosen by the consumer
  subject,          // connected wallet and SBT owner
  nonce,            // uint256 decimal string
  verifier,         // exact configured PredicateVerifier
  chainId           // exact configured chain
}
```

The response is an artifact:

```ts
{
  attestation: {
    consumer: `0x${string}`;
    context: `0x${string}`;
    predicate: `0x${string}`;
    result: boolean;
    subject: `0x${string}`;
    epoch: number;
    nonce: string;
  };
  signature: `0x${string}`;
  digest: `0x${string}`;
  issuer: `0x${string}`;
}
```

The EIP-712 domain is pinned to:

```text
name              ProofOfHumanityPredicate
version           1
chainId           target chain
verifyingContract exact PredicateVerifier deployment
```

## Read-only integration

Use this only when replay is harmless:

```ts
const allowed = await checkPredicateArtifact({
  artifact,
  rpcUrl: network.rpcUrl,
  presenter: connectedWallet,
  consumer: MY_APP_ADDRESS,
});

if (!allowed) throw new Error("predicate not satisfied");
```

Independently recover the signature before accepting an API response:

```ts
const recovered = await recoverPredicateIssuer(artifact);
if (recovered.toLowerCase() !== configuredIssuer.toLowerCase()) {
  throw new Error("unexpected predicate issuer");
}
```

## Stateful Solidity integration

The consuming contract, not an EOA or relay, calls `consume`. This makes
`att.consumer == msg.sender` enforceable and spends the replay key.

```solidity
bytes32 internal constant AGE_18 = keccak256("age>=18");
bytes32 internal constant JOIN_CONTEXT = keccak256("community:season-1");

function join(PredicateVerifier.PredicateAttestation calldata att, bytes calldata signature) external {
    require(att.consumer == address(this), "wrong consumer");
    require(att.context == JOIN_CONTEXT, "wrong context");
    require(att.predicate == AGE_18 && att.result, "18+ required");
    require(verifier.consume(att, signature, msg.sender), "predicate failed");
    _addMember(msg.sender);
}
```

`consume` also enforces issuer recovery, subject/presenter equality, freshness, and single use of
`(subject, consumer, context, nonce)`.

## Security rules

- Maintain your own chain ID, contract address, issuer, descriptor, and context allowlists.
- Require `result == true`; a valid signature can intentionally attest `false`.
- Use `consume` for votes, claims, mints, grants, or any action where replay matters.
- Never log the holder's `HumanCredential`, Self proof payload, vault plaintext, PRF output, vault key, or
  passport attributes. v1 credentials remain session-only. v2 may persist only the authenticated ciphertext
  envelope after the passkey/recovery integration passes its security gate.
- Treat the issuer as an operational signer with no gas funds; keep the owner as a separate multisig.
- A configured `prover()` address is a separate security release. Zero means issuer path only.

See [`DEPLOY.md`](DEPLOY.md) for the mainnet environment and release gate, and
[`contracts/PHASE2.md`](../../contracts/PHASE2.md) for the testnet deployment workflow.
