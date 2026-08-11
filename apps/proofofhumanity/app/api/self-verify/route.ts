/**
 * The Proof-of-Humanity relay + issuer (adapted from apps/wallet/app/api/self-verify/route.ts).
 *
 * Unlike the wallet's relay — which only ABI-encoded calldata for the chain to re-verify — THIS
 * route is the TRUST ROOT: it verifies the Self proof off-chain and SIGNS the humanity voucher.
 *
 * When a user completes verification, the Self mobile app POSTs
 * `{ attestationId, proof, publicSignals, userContextData }` here. This handler:
 *
 *   1. runs `@selfxyz/core`'s `SelfBackendVerifier.verify(...)` — Groth16 pairing + Self identity
 *      registry membership (against the Celo hub) + scope/endpoint binding + OFAC config. This is
 *      what proves a UNIQUE HUMAN and yields the nullifier;
 *   2. on `isValidDetails.isValid`, builds a MINIMAL `HumanityVoucher` = { to, nullifier, epoch }
 *      bound to the proof's `userIdentifier` address (`lib/voucher.ts::buildVoucher`). NO attributes
 *      (nationality / gender / age) are mapped in — the credential carries no personal data;
 *   3. signs ONE voucher per configured chain with the issuer key (each chain has its own EIP-712
 *      domain), and stores the set keyed by the lowercased recipient address for the client to poll.
 *
 * TRUST BOUNDARY: this route DECIDES validity (it is the issuer). Its signature is what
 * `mintWithVoucher` recovers and requires `== issuer`. Guard `ISSUER_PRIVATE_KEY` accordingly.
 *
 * STORAGE BOUNDARY: the callback handoff is process-local, bounded, and expires after ten minutes.
 * The first production release must use one sticky Node worker. Horizontal scaling requires a
 * separately reviewed shared encrypted-store adapter because derived claims are sensitive.
 *
 * REACHABILITY CAVEAT: `verify()` needs the public `endpoint` to match the frontend's, and reaches
 * the Celo identity hub over the network; a real proof is generated on a phone, so a true
 * end-to-end run needs `NEXT_PUBLIC_SELF_ENDPOINT` publicly reachable (tunnel in dev).
 */

import { NextRequest, NextResponse } from "next/server";
import {
  SelfBackendVerifier,
  AllIds,
  type IConfigStorage,
  type VerificationConfig,
} from "@selfxyz/core";
import type { Address } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  buildVoucher,
  epochNow,
  serializeVoucher,
  signVoucher,
  type SerializedVoucher,
} from "../../lib/voucher";
import {
  ageFlagsFromThresholds,
  nationalityToBytes3,
  serializeHumanCredential,
  signHumanCredential,
  type HumanCredential,
  type SerializedHumanCredential,
} from "../../lib/predicate";
import {
  decodeDisclosureProfile,
  decodeDisclosureRequest,
  encodeDisclosureProfile,
  verificationConfigFor,
  type DisclosureProfile,
} from "../../lib/disclosure-profile";
import { CHAINS, SELF_SCOPE, SELF_ENDPOINT, SELF_MOCK_PASSPORT } from "../../config";
import { getIssuerPrivateKey } from "../../server-config";
import {
  deleteVerificationRecord,
  getVerificationRecord,
  rateLimit,
  setVerificationRecord,
} from "../../lib/server/verification-store";

// Node.js runtime: the process-local handoff must persist across requests, and @selfxyz/core pulls in
// Node-only crypto (snarkjs, node-forge) that the edge runtime cannot run.
export const runtime = "nodejs";

/** A voucher signed for one specific chain. */
interface SignedForChain {
  chainId: number;
  name: string;
  pohAddress: Address;
  voucher: SerializedVoucher;
  signature: `0x${string}`;
}

interface RelayRecord {
  status: "ready" | "error";
  /** The proof's anonymous nullifier + validity epoch, for the UI to preview before minting. */
  proof?: {
    nullifier: string;
    epoch: number;
  };
  vouchers?: SignedForChain[];
  /**
   * The PRIVATE, held HumanCredential the issuer additionally signs at verification.
   * The holder stores this off-chain (sessionStorage) and later presents it
   * to `/api/predicate` to prove a predicate. It carries the raw predicate inputs
   * (age flags / nationality / OFAC-clear) the issuer read out of the Self disclosures;
   * it is NEVER put on-chain. (With an OFAC-only disclosure, only `ofacClear` is set.)
   */
  credential?: SerializedHumanCredential;
  credentialSig?: `0x${string}`;
  issuer?: Address;
  error?: string;
  receivedAt: number;
}

/**
 * Self asks the store for a config id derived from the proof-bound userDefinedData before it
 * verifies the configured age/OFAC policy. Only our fixed profile grammar is accepted.
 */
class DisclosureConfigStore implements IConfigStorage {
  async getConfig(id: string): Promise<VerificationConfig> {
    const profile = decodeDisclosureProfile(id);
    if (!profile) throw new Error("Unsupported disclosure profile.");
    return verificationConfigFor(profile);
  }

  async setConfig(): Promise<boolean> {
    return false;
  }

  async getActionId(_userIdentifier: string, data: string): Promise<string> {
    const request = decodeDisclosureRequest(data);
    if (!request) throw new Error("Invalid proof disclosure profile or session.");
    return encodeDisclosureProfile(request.profile);
  }
}

let cachedVerifier: SelfBackendVerifier | null = null;
function getVerifier(): SelfBackendVerifier {
  if (!SELF_ENDPOINT) {
    throw new Error(
      "NEXT_PUBLIC_SELF_ENDPOINT is not set — the backend verifier needs the same public endpoint the frontend advertises.",
    );
  }
  if (!cachedVerifier) {
    cachedVerifier = new SelfBackendVerifier(
      SELF_SCOPE,
      SELF_ENDPOINT,
      SELF_MOCK_PASSPORT,
      AllIds,
      new DisclosureConfigStore(),
      "hex",
    );
  }
  return cachedVerifier;
}

interface SelfPostBody {
  attestationId: 1 | 2;
  proof: unknown;
  publicSignals: unknown;
  userContextData: string;
}

function isSelfPostBody(b: unknown): b is SelfPostBody {
  if (!b || typeof b !== "object") return false;
  const o = b as Record<string, unknown>;
  return (
    (o.attestationId === 1 || o.attestationId === 2) &&
    typeof o.proof === "object" &&
    o.proof !== null &&
    Array.isArray(o.publicSignals) &&
    typeof o.userContextData === "string"
  );
}

export async function POST(req: NextRequest) {
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > 2_000_000) {
    return NextResponse.json({ ok: false, error: "Self proof payload is too large." }, { status: 413 });
  }
  const source = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "self-callback";
  const limit = rateLimit("self-callback", source, 30, 60);
  if (!limit.allowed) {
    return NextResponse.json(
      { ok: false, error: "Too many verification callbacks." },
      { status: 429, headers: { "retry-after": String(limit.retryAfter) } },
    );
  }
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body." }, { status: 400 });
  }

  if (!isSelfPostBody(body)) {
    return NextResponse.json(
      { ok: false, error: "Expected { attestationId, proof, publicSignals, userContextData }." },
      { status: 400 },
    );
  }

  // 1) Verify the Self proof off-chain (this is the trust decision).
  let result: Awaited<ReturnType<SelfBackendVerifier["verify"]>>;
  try {
    result = await getVerifier().verify(
      body.attestationId,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      body.proof as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      body.publicSignals as any,
      body.userContextData,
    );
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ ok: false, error: `Verification failed: ${error}` }, { status: 400 });
  }

  const disclosureRequest = decodeDisclosureRequest(result.userData.userDefinedData);
  if (!disclosureRequest) {
    return NextResponse.json(
      { ok: false, error: "Self proof carried an unsupported disclosure profile or browser session." },
      { status: 400 },
    );
  }
  const profile: DisclosureProfile = disclosureRequest.profile;
  const validity = result.isValidDetails;
  const policyValid = validity.isValid && validity.isOfacValid && (!profile.age || validity.isMinimumAgeValid);
  if (!policyValid) {
    const record: RelayRecord = {
      status: "error",
      error: !validity.isOfacValid
          ? "Sanctions screening did not pass."
          : profile.age && !validity.isMinimumAgeValid
            ? `The requested ${profile.age}+ threshold was not proven.`
            : "Self proof did not verify.",
      receivedAt: Date.now(),
    };
    const who = result.userData.userIdentifier?.toLowerCase();
    if (who) setVerificationRecord(who, disclosureRequest.session, record);
    return NextResponse.json({ ok: false, error: record.error }, { status: 400 });
  }

  // 2) Build a MINIMAL voucher bound to the proof's own address. Only the nullifier (unique human)
  //    and the current validity epoch — no attributes are read out of the proof.
  const to = result.userData.userIdentifier as Address;
  if (!to || !/^0x[0-9a-fA-F]{40}$/.test(to)) {
    return NextResponse.json(
      { ok: false, error: "Proof did not carry a valid hex userIdentifier (the recipient address)." },
      { status: 400 },
    );
  }

  const epoch = epochNow();
  const voucher = buildVoucher({ discloseOutput: { nullifier: result.discloseOutput.nullifier }, to, epoch });
  const issuerPrivateKey = getIssuerPrivateKey();
  const issuer = privateKeyToAccount(issuerPrivateKey).address;

  // 3) Sign one voucher per DEPLOYED chain (distinct EIP-712 domain per chain).
  const vouchers: SignedForChain[] = [];
  for (const chain of CHAINS) {
    if (/^0x0{40}$/i.test(chain.pohAddress)) continue; // skip not-yet-deployed chains
    const signature = await signVoucher(issuerPrivateKey, voucher, chain.chainId, chain.pohAddress);
    vouchers.push({
      chainId: chain.chainId,
      name: chain.name,
      pohAddress: chain.pohAddress,
      voucher: serializeVoucher(voucher),
      signature,
    });
  }

  // 4) Additionally issue the PRIVATE HumanCredential the holder keeps for predicate
  //    proofs. Attributes are read out of the Self disclosures the human consented to:
  //    with the base OFAC-only flow only `ofacClear` is populated; enabling age /
  //    nationality disclosures on the SelfAppBuilder populates the rest. It is signed
  //    with a PORTABLE domain (no chain), never stored on-chain.
  const disclose = result.discloseOutput as {
    nationality?: string;
    minimumAge?: string;
    ofac?: boolean[];
  };
  const ofacClear = validity.isOfacValid;
  const nat =
    profile.nationality && disclose.nationality && /^[A-Za-z]{3}$/.test(disclose.nationality)
      ? nationalityToBytes3(disclose.nationality)
      : ("0x000000" as `0x${string}`);
  const credential: HumanCredential = {
    nullifier: voucher.nullifier,
    ageFlags: ageFlagsFromThresholds({ over18: profile.age === 18 || profile.age === 21, over21: profile.age === 21 }),
    nationality: nat,
    ofacClear,
    epoch: voucher.epoch,
  };
  const credentialSig = await signHumanCredential(issuerPrivateKey, credential);

  const record: RelayRecord = {
    status: "ready",
    proof: {
      nullifier: voucher.nullifier.toString(),
      epoch: voucher.epoch,
    },
    vouchers,
    credential: serializeHumanCredential(credential),
    credentialSig,
    issuer,
    receivedAt: Date.now(),
  };
  setVerificationRecord(to, disclosureRequest.session, record);

  return NextResponse.json({
    ok: true,
    to,
    signedChains: vouchers.map((v) => v.chainId),
    note:
      vouchers.length === 0
        ? "Proof verified, but no chain has a deployed ProofOfHumanity address configured — set NEXT_PUBLIC_<CHAIN>_POH."
        : undefined,
  });
}

/** GET /api/self-verify?address=0x… with x-poh-verification-session — both are required to poll. */
export async function GET(req: NextRequest) {
  const address = req.nextUrl.searchParams.get("address")?.toLowerCase();
  const session = req.headers.get("x-poh-verification-session")?.toLowerCase();
  if (!address || !/^0x[0-9a-f]{40}$/.test(address) || !session || !/^[0-9a-f]{32}$/.test(session)) {
    return NextResponse.json({ ok: false, error: "A valid `address` and 128-bit `session` are required." }, { status: 400 });
  }
  const record = getVerificationRecord<RelayRecord>(address, session);
  if (!record) return NextResponse.json({ status: "pending" }, { headers: { "cache-control": "no-store" } });
  return NextResponse.json(record, { headers: { "cache-control": "no-store" } });
}

/** DELETE /api/self-verify?address=0x… with the session header — drop a consumed record. */
export async function DELETE(req: NextRequest) {
  const address = req.nextUrl.searchParams.get("address")?.toLowerCase();
  const session = req.headers.get("x-poh-verification-session")?.toLowerCase();
  if (address && session && /^0x[0-9a-f]{40}$/.test(address) && /^[0-9a-f]{32}$/.test(session)) {
    deleteVerificationRecord(address, session);
  }
  return NextResponse.json({ ok: true });
}
