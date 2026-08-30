# Quick Launch v1 predicate integration

PoH Quick Launch v1 exposes one issuer-attested predicate path on Base Sepolia. Self verifies the
requested passport facts on the holder's phone. The application issuer then signs one Boolean result
for one consumer, context, subject, chain, verifier, epoch, and nonce.

The Self passport proof is zero-knowledge. The resulting v1 predicate artifact is **not** a
holder-generated ZK proof: consumers trust the configured issuer to evaluate the browser-held
credential correctly. They can independently verify the signature, EIP-712 domain, request bindings,
freshness, live soulbound token, and deployed verifier.

Custom v2 circuits, the policy designer, portable passkey vault, Self issuance bridge, and
`IPredicateProver` activation are outside this release. Their research remains under `docs/specs/`, but
none is a Quick Launch route or API method and `PredicateVerifier.prover()` must remain zero.

## User flow

1. The holder chooses optional age and nationality disclosures before opening Self. OFAC/sanctions
   clearance is required by the current profile.
2. `/api/self-verify` verifies the Self proof and issues both the Base Sepolia humanity voucher and a
   short-lived private `HumanCredential` to the address/session capability.
3. The browser keeps that credential in `sessionStorage`. Closing the tab clears it.
4. After the soulbound token is minted, `/api/predicate` verifies the held credential signature,
   freshness, token ownership, contract pair, and live issuer addresses.
5. The route evaluates one descriptor and signs one `PredicateAttestation`.
6. The app locally recovers the signer and calls `PredicateVerifier.check` on Base Sepolia before it
   presents the artifact as accepted.

## Canonical descriptors

| Descriptor | Meaning |
|---|---|
| `age>=18` | the Self session proved the 18+ threshold |
| `age>=21` | the Self session proved the 21+ threshold |
| `nationality=ARG` | the disclosed ISO 3166-1 alpha-3 nationality equals `ARG` |
| `sanctions-clear` | the configured Self OFAC screening passed |

Descriptors are exact and case-sensitive. Nationality codes are uppercase ISO alpha-3. No aliases,
spaces, arbitrary expressions, or unbounded input are accepted.

## What the consumer sees

The consumer receives the descriptor hash, Boolean result, subject wallet, consumer, context, epoch,
nonce, verifier, chain ID, and issuer signature. It does not receive the passport, name, document
number, date of birth, exact age, or an undisclosed nationality.

The v1 artifact is consumer-bound but **not unlinkable when the same subject wallet is reused**. The
subject address is explicit, so two consumers can correlate it. Quick Launch must not claim
cross-consumer unlinkability. A dedicated credential wallet reduces linkage to unrelated activity but
does not hide that wallet from predicate consumers.

The issuer sees the selected threshold/nationality and sanctions result while issuing the private
credential. The held credential is not currently passkey-encrypted. Production-safe passkey protection
is a later Quick Launch slice; loss/recovery should re-run Self rather than reuse the experimental v2
vault.

## Request an attestation

```ts
import { predicateContext } from "@ubi2/sdk";

const response = await fetch("https://proofofhumanity.org/api/predicate", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    credential,
    credentialSig,
    predicate: "age>=18",
    consumer: APP_OR_CONTRACT_ADDRESS,
    context: predicateContext("community:season-1"),
    subject: connectedWallet,
    nonce: cryptoNonce.toString(),
    verifier: "0x2051D33c2F10CDd3739324afc4C6fD957564a9D6",
    chainId: 84532,
  }),
});

if (!response.ok) throw new Error("predicate refused");
const { attestation, signature } = await response.json();
```

Before accepting it, require the exact descriptor hash, `result === true`, expected subject, consumer,
context, Base Sepolia chain ID, reviewed verifier address, fresh epoch, and issuer signature. For a
state-changing contract action, call `consume` atomically; `check` is only for replay-insensitive reads.

## Failure boundary

The API fails closed when any of these are true:

- chain ID is not `84532` or verifier is not the pinned Base Sepolia deployment;
- the held credential signature is malformed, from another issuer, stale, or in the future;
- the subject does not own the live token for the credential nullifier;
- the soulbound token is expired;
- the PoH and predicate contracts do not expose the configured issuer;
- the descriptor, address, context, nonce, or credential field is malformed or oversized;
- a per-source or per-subject rate limit is exceeded;
- the Base Sepolia RPC cannot prove the binding.

Do not log Self callback bodies, held credentials, passport-derived attributes, issuer material, sponsor
material, or secret-bearing RPC URLs. The first release remains one sticky Node process because the
ten-minute callback handoff and limits are process-local.
