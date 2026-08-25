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
 *   2. for the existing v1 request, builds and signs the minimal multi-chain humanity voucher plus
 *      the holder's private issuer-attested predicate credential;
 *   3. for an explicit v2 request carrying a proof-bound holder commitment, derives a registry-scoped
 *      duplicate key in memory and returns only a short-lived authorization for the immutable bridge.
 *
 * TRUST BOUNDARY: this route DECIDES validity. V1 trusts `ISSUER_PRIVATE_KEY`; transitional v2
 * trusts the separate immutable bridge authority key. Guard and isolate both roles accordingly.
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
} from "../../lib/voucher";
import {
  ageFlagsFromThresholds,
  nationalityToBytes3,
  serializeHumanCredential,
  signHumanCredential,
  type HumanCredential,
} from "../../lib/predicate";
import {
  decodeDisclosureProfile,
  decodeDisclosureRequest,
  encodeDisclosureProfile,
  verificationConfigFor,
  type DisclosureProfile,
} from "../../lib/disclosure-profile";
import { CHAINS, SELF_SCOPE, SELF_ENDPOINT, SELF_MOCK_PASSPORT } from "../../config";
import { getIssuerPrivateKey, getSponsoredMintServerConfig } from "../../server-config";
import {
  deleteVerificationRecord,
  getVerificationRecord,
  rateLimit,
  setVerificationRecord,
  updateVerificationRecord,
  VERIFICATION_RECORD_TTL_MS,
} from "../../lib/server/verification-store";
import {
  buildZkSelfIssuanceGrant,
  refreshZkSelfIssuanceArtifact,
  ZkSelfIssuanceAlreadyConsumedError,
  ZkSelfIssuanceGrantExpiredError,
} from "../../lib/server/zk-self-issuance";
import {
  publicRelayRecord,
  type RelayRecord,
  type SignedForChain,
} from "../../lib/verification-record";
import { verificationCapability } from "../../lib/server/verification-capability";

// Node.js runtime: the process-local handoff must persist across requests, and @selfxyz/core pulls in
// Node-only crypto (snarkjs, node-forge) that the edge runtime cannot run.
export const runtime = "nodejs";

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

  // The v2 request is intentionally disjoint from legacy voucher issuance. It
  // returns no raw Self nullifier, public NFT voucher or attribute credential;
  // only the registry-scoped duplicate key inside a bridge authorization.
  if (disclosureRequest.credentialCommitment) {
    if (body.attestationId !== 1) {
      return NextResponse.json(
        { ok: false, error: "V2 private-credential issuance currently requires a Self e-passport proof." },
        { status: 400 },
      );
    }
    try {
      const expiresAtMs = Date.now() + VERIFICATION_RECORD_TTL_MS;
      const { grant: zkIssuanceGrant, artifact: zkIssuance } = await buildZkSelfIssuanceGrant({
        subject: to,
        rawSelfNullifier: BigInt(result.discloseOutput.nullifier),
        credentialCommitment: BigInt(disclosureRequest.credentialCommitment),
        expiresAtMs,
      });
      const record: RelayRecord = {
        status: "ready",
        zkIssuance,
        zkIssuanceGrant,
        receivedAt: Date.now(),
      };
      setVerificationRecord(to, disclosureRequest.session, record, expiresAtMs);
      return NextResponse.json({
        ok: true,
        to,
        zkIssuanceChainId: zkIssuance.chainId,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown v2 issuance error.";
      const status =
        error instanceof ZkSelfIssuanceAlreadyConsumedError
          ? 409
          : error instanceof ZkSelfIssuanceGrantExpiredError
            ? 410
            : 503;
      const record: RelayRecord = {
        status: "error",
        error: `Private-credential issuance is unavailable: ${message}`,
        receivedAt: Date.now(),
      };
      setVerificationRecord(to, disclosureRequest.session, record);
      return NextResponse.json({ ok: false, error: record.error }, { status });
    }
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
  const capability = verificationCapability(req);
  if (!capability) {
    return NextResponse.json({ ok: false, error: "A valid `address` and 128-bit `session` are required." }, { status: 400 });
  }
  const record = getVerificationRecord<RelayRecord>(capability.address, capability.session);
  if (!record) return NextResponse.json({ status: "pending" }, { headers: { "cache-control": "no-store" } });
  let sponsoredChainIds: number[] = [];
  if (record.status === "ready" && record.vouchers) {
    try {
      const config = getSponsoredMintServerConfig();
      sponsoredChainIds = config
        ? config.enabledChainIds.filter((chainId) => record.vouchers?.some((voucher) => voucher.chainId === chainId))
        : [];
    } catch {
      // Malformed or partial sponsor configuration disables the UI path without breaking proof polling.
    }
  }
  return NextResponse.json(
    { ...publicRelayRecord(record), sponsoredChainIds },
    { headers: { "cache-control": "no-store" } },
  );
}

/**
 * PATCH the same address/session capability to recover from an expired artifact or a slot/epoch
 * race. Only the race-prone authorization fields are re-read and re-signed; the original
 * proof-derived subject, duplicate key, commitment and hard verification expiry remain fixed.
 */
export async function PATCH(req: NextRequest) {
  const capability = verificationCapability(req);
  if (!capability) {
    return NextResponse.json(
      { ok: false, error: "A valid `address` and 128-bit `session` are required." },
      { status: 400 },
    );
  }
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (Number.isFinite(contentLength) && contentLength > 0) {
    return NextResponse.json(
      { ok: false, error: "Issuance refresh does not accept a request body." },
      { status: 400, headers: { "cache-control": "no-store" } },
    );
  }

  const source = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "issuance-refresh";
  const sourceLimit = rateLimit("self-issuance-refresh-source", source, 30, 60);
  const capabilityLimit = rateLimit(
    "self-issuance-refresh-capability",
    `${capability.address}:${capability.session}`,
    8,
    60,
  );
  if (!sourceLimit.allowed || !capabilityLimit.allowed) {
    const retryAfter = Math.max(sourceLimit.retryAfter, capabilityLimit.retryAfter);
    return NextResponse.json(
      { ok: false, error: "Too many issuance refresh attempts. Try again shortly." },
      { status: 429, headers: { "retry-after": String(retryAfter), "cache-control": "no-store" } },
    );
  }

  const record = getVerificationRecord<RelayRecord>(capability.address, capability.session);
  if (!record) {
    return NextResponse.json(
      { ok: false, error: "The verified issuance session expired; scan the passport again." },
      { status: 410, headers: { "cache-control": "no-store" } },
    );
  }
  if (record.status !== "ready" || !record.zkIssuance || !record.zkIssuanceGrant) {
    return NextResponse.json(
      { ok: false, error: "This verification session does not contain a refreshable v2 issuance." },
      { status: 409, headers: { "cache-control": "no-store" } },
    );
  }
  if (record.zkIssuanceGrant.subject.toLowerCase() !== capability.address) {
    return NextResponse.json(
      { ok: false, error: "The verification capability does not match the proof-bound subject." },
      { status: 403, headers: { "cache-control": "no-store" } },
    );
  }

  try {
    const zkIssuance = await refreshZkSelfIssuanceArtifact(record.zkIssuanceGrant);
    const updated: RelayRecord = { ...record, zkIssuance };
    if (!updateVerificationRecord(capability.address, capability.session, updated)) {
      return NextResponse.json(
        { ok: false, error: "The verified issuance session expired; scan the passport again." },
        { status: 410, headers: { "cache-control": "no-store" } },
      );
    }
    return NextResponse.json(
      { ok: true, zkIssuance },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    if (error instanceof ZkSelfIssuanceGrantExpiredError) {
      return NextResponse.json(
        { ok: false, error: error.message },
        { status: 410, headers: { "cache-control": "no-store" } },
      );
    }
    if (error instanceof ZkSelfIssuanceAlreadyConsumedError) {
      return NextResponse.json(
        { ok: false, error: error.message },
        { status: 409, headers: { "cache-control": "no-store" } },
      );
    }
    return NextResponse.json(
      { ok: false, error: "Issuance authorization refresh is temporarily unavailable." },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }
}

/** DELETE /api/self-verify?address=0x… with the session header — drop a consumed record. */
export async function DELETE(req: NextRequest) {
  const capability = verificationCapability(req);
  if (capability) {
    deleteVerificationRecord(capability.address, capability.session);
  }
  return NextResponse.json({ ok: true });
}
