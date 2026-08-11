/**
 * DEMO-ONLY HumanCredential issuance — so the "Prove you're 18+" flow works in a
 * browser without a phone / passport scan.
 *
 * In the REAL flow, the issuer mints a `HumanCredential` inside `/api/self-verify`
 * right after `SelfBackendVerifier.verify(...)` succeeds, populated from the Self
 * disclosures the human consented to (see that route). A real, OFAC-only Self
 * proof discloses no age, so a genuine credential could not answer "age>=18".
 *
 * This route fabricates a credential with DEMO attributes (an adult, sanctions-
 * clear, nationality ARG) and signs it with the issuer key, purely to drive the
 * end-to-end predicate demo. It is HARD-GATED to non-production: it refuses to
 * run when `NODE_ENV === "production"` unless `POH_ENABLE_DEMO_CREDENTIAL=1` is
 * explicitly set, so it can never mint fake credentials on a real deployment.
 */

import { NextRequest, NextResponse } from "next/server";
import { privateKeyToAccount } from "viem/accounts";
import type { Address } from "viem";
import {
  ageFlagsFromThresholds,
  epochNow,
  nationalityToBytes3,
  serializeHumanCredential,
  signHumanCredential,
  type HumanCredential,
} from "../../../lib/predicate";
import { getIssuerPrivateKey } from "../../../server-config";

export const runtime = "nodejs";

function demoEnabled(): boolean {
  if (process.env.NODE_ENV !== "production") return true;
  return process.env.POH_ENABLE_DEMO_CREDENTIAL === "1";
}

export async function POST(_req: NextRequest) {
  if (!demoEnabled()) {
    return NextResponse.json(
      { ok: false, error: "Demo credential issuance is disabled in production." },
      { status: 403 },
    );
  }

  // A demo human: over 21 (⇒ over 18), sanctions-clear, nationality ARG.
  const credential: HumanCredential = {
    // A stable, obviously-fake demo nullifier (a BN254-ish field element).
    nullifier: 111111111111111111111111111111111111111111111111111n,
    ageFlags: ageFlagsFromThresholds({ over21: true }),
    nationality: nationalityToBytes3("ARG"),
    ofacClear: true,
    epoch: epochNow(),
  };

  const issuerPrivateKey = getIssuerPrivateKey();
  const signature = await signHumanCredential(issuerPrivateKey, credential);
  const issuer = privateKeyToAccount(issuerPrivateKey).address as Address;

  return NextResponse.json({
    ok: true,
    demo: true,
    credential: serializeHumanCredential(credential),
    credentialSig: signature,
    issuer,
    note: "DEMO credential — attributes are fabricated for the predicate demo, not derived from a real Self proof.",
  });
}
