/**
 * THE PREDICATE ISSUER (v1) — attest a yes/no predicate over a held HumanCredential.
 *
 * A holder who owns a private `HumanCredential` (issued at Self verification and
 * kept off-chain) asks this route to prove ONE predicate ("age>=18", …) to ONE
 * consumer. The issuer:
 *
 *   1. re-verifies the credential signature recovers to ITS OWN issuer key
 *      (`verifyHumanCredential`) — i.e. this is a credential it really issued;
 *   2. computes the boolean `result` from the credential's attributes using the
 *      descriptor grammar (`evalPredicate`) — the raw attributes NEVER leave the
 *      server;
 *   3. binds the result into a `PredicateAttestation` for exactly one
 *      `{ consumer, context, subject }` on one `{ chainId, verifier }`, and signs
 *      it. Only the boolean crosses to the consumer.
 *
 * ┌── v1 IS ISSUER-ATTESTED ──────────────────────────────────────────────────┐
 * │ The ISSUER is the prover here: it holds the trust that the boolean matches │
 * │ the credential. The trustless v2 moves this computation to a holder-side   │
 * │ ZK proof over the held credential, verified through the `IPredicateProver` │
 * │ seam on `PredicateVerifier` — the on-chain `consume` ABI is unchanged. The │
 * │ credential attributes read here are exactly that circuit's witness.        │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * SUBJECT BINDING (honest note): the HumanCredential is keyed by `nullifier`, not
 * by an address, and v1 does not cryptographically tie the credential to the
 * presenting `subject` address. That binding is enforced ON-CHAIN instead: the
 * demo consumer (`SybilResistantVote`) requires `poh.ownerOf(tokenId) == msg.sender`
 * AND `att.subject == msg.sender`, so the SBT ownership is what ties an address
 * to the unique human. v2's holder-proof binds credential → subject directly.
 */

import { NextRequest, NextResponse } from "next/server";
import { getAddress, isAddress, isHex, type Address, type Hex } from "viem";
import {
  deserializeHumanCredential,
  descriptorHash,
  epochNow,
  evalPredicate,
  hashPredicateAttestation,
  serializePredicateAttestation,
  signPredicateAttestation,
  verifyHumanCredential,
  type PredicateAttestation,
  type SerializedHumanCredential,
} from "../../lib/predicate";
import { ISSUER_PRIVATE_KEY } from "../../config";
import { privateKeyToAccount } from "viem/accounts";

// Node.js runtime: signing uses the server-only issuer key + Node crypto.
export const runtime = "nodejs";

interface PredicateRequestBody {
  /** The holder's private HumanCredential (JSON-safe form). */
  credential: SerializedHumanCredential;
  /** The issuer's signature over that credential. */
  credentialSig: Hex;
  /** The CANONICAL DESCRIPTOR to prove (e.g. "age>=18"), NOT its hash — the
   *  issuer needs the plaintext to evaluate; it hashes it into the attestation. */
  predicate: string;
  /** The verifying consumer contract/app. */
  consumer: Address;
  /** Consumer-defined scope (bytes32). */
  context: Hex;
  /** The presenting human's address. */
  subject: Address;
  /** Anti-replay salt (uint256 as decimal string). */
  nonce: string;
  /** The deployed PredicateVerifier (EIP-712 verifyingContract). */
  verifier: Address;
  /** The chain the verifier lives on (EIP-712 chainId). */
  chainId: number;
}

function isBody(b: unknown): b is PredicateRequestBody {
  if (!b || typeof b !== "object") return false;
  const o = b as Record<string, unknown>;
  const cred = o.credential as Record<string, unknown> | undefined;
  return (
    !!cred &&
    typeof cred.nullifier === "string" &&
    typeof cred.ageFlags === "number" &&
    typeof cred.nationality === "string" &&
    typeof cred.ofacClear === "boolean" &&
    typeof cred.epoch === "number" &&
    typeof o.credentialSig === "string" &&
    typeof o.predicate === "string" &&
    typeof o.consumer === "string" &&
    typeof o.context === "string" &&
    typeof o.subject === "string" &&
    typeof o.nonce === "string" &&
    typeof o.verifier === "string" &&
    typeof o.chainId === "number"
  );
}

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body." }, { status: 400 });
  }
  if (!isBody(body)) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "Expected { credential, credentialSig, predicate, consumer, context, subject, nonce, verifier, chainId }.",
      },
      { status: 400 },
    );
  }

  // Structural validation of the addresses / hex.
  if (!isAddress(body.consumer) || !isAddress(body.subject) || !isAddress(body.verifier)) {
    return NextResponse.json({ ok: false, error: "consumer / subject / verifier must be addresses." }, { status: 400 });
  }
  if (!isHex(body.context) || body.context.length !== 66) {
    return NextResponse.json({ ok: false, error: "context must be a 32-byte hex string." }, { status: 400 });
  }
  if (!isHex(body.credentialSig)) {
    return NextResponse.json({ ok: false, error: "credentialSig must be hex." }, { status: 400 });
  }

  const issuer = privateKeyToAccount(ISSUER_PRIVATE_KEY).address as Address;
  const credential = deserializeHumanCredential(body.credential);

  // 1) The credential must be one THIS issuer signed.
  let credentialOk = false;
  try {
    credentialOk = await verifyHumanCredential(credential, body.credentialSig, issuer);
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: `Credential signature malformed: ${e instanceof Error ? e.message : String(e)}` },
      { status: 400 },
    );
  }
  if (!credentialOk) {
    return NextResponse.json(
      { ok: false, error: "Credential was not signed by this issuer — refusing to attest." },
      { status: 401 },
    );
  }

  // 1b) Freshness: the credential's epoch must be within the validity window.
  const nowEpoch = epochNow();
  if (credential.epoch > nowEpoch) {
    return NextResponse.json({ ok: false, error: "Credential epoch is in the future." }, { status: 400 });
  }

  // 2) Compute the boolean from the credential attributes (raw values never leave here).
  let result: boolean;
  let predicateHash: Hex;
  try {
    result = evalPredicate(body.predicate, {
      ageFlags: credential.ageFlags,
      nationality: credential.nationality,
      ofacClear: credential.ofacClear,
    });
    predicateHash = descriptorHash(body.predicate);
  } catch (e) {
    return NextResponse.json(
      { ok: false, error: `Unsupported predicate: ${e instanceof Error ? e.message : String(e)}` },
      { status: 400 },
    );
  }

  // 3) Bind + sign the attestation for exactly this consumer / context / subject.
  let nonce: bigint;
  try {
    nonce = BigInt(body.nonce);
  } catch {
    return NextResponse.json({ ok: false, error: "nonce must be a uint256 decimal string." }, { status: 400 });
  }

  const att: PredicateAttestation = {
    consumer: getAddress(body.consumer),
    context: body.context,
    predicate: predicateHash,
    result,
    subject: getAddress(body.subject),
    epoch: credential.epoch,
    nonce,
  };

  const verifier = getAddress(body.verifier);
  const signature = await signPredicateAttestation(ISSUER_PRIVATE_KEY, att, body.chainId, verifier);
  const digest = hashPredicateAttestation(att, body.chainId, verifier);

  return NextResponse.json({
    ok: true,
    // Only the boolean + the bound envelope — no age / nationality / OFAC value.
    attestation: serializePredicateAttestation(att),
    signature,
    digest,
    result,
    issuer,
  });
}
