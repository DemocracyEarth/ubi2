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
 *      registry membership (against the Celo hub) + scope/endpoint binding + OFAC config;
 *   2. on `isValidDetails.isValid`, maps `discloseOutput` → a `HumanityVoucher` bound to the
 *      proof's `userIdentifier` address (`lib/voucher.ts::buildVoucherFromDisclose`);
 *   3. signs ONE voucher per configured chain with the issuer key (each chain has its own EIP-712
 *      domain), and stores the set keyed by the lowercased recipient address for the client to poll.
 *
 * TRUST BOUNDARY: this route DECIDES validity (it is the issuer). Its signature is what
 * `mintWithVoucher` recovers and requires `== issuer`. Guard `ISSUER_PRIVATE_KEY` accordingly.
 *
 * STORAGE CAVEAT (devnet/demo): the store is an in-process `Map` — fine for one `next` worker, NOT
 * durable across restarts / multiple instances. Production needs a shared store (Redis/KV/DB).
 *
 * REACHABILITY CAVEAT: `verify()` needs the public `endpoint` to match the frontend's, and reaches
 * the Celo identity hub over the network; a real proof is generated on a phone, so a true
 * end-to-end run needs `NEXT_PUBLIC_SELF_ENDPOINT` publicly reachable (tunnel in dev).
 */

import { NextRequest, NextResponse } from "next/server";
import {
  SelfBackendVerifier,
  DefaultConfigStore,
  AllIds,
  type VerificationConfig,
} from "@selfxyz/core";
import type { Address } from "viem";
import {
  buildVoucherFromDisclose,
  serializeVoucher,
  signVoucher,
  type SerializedVoucher,
} from "../../lib/voucher";
import {
  CHAINS,
  SELF_SCOPE,
  SELF_ENDPOINT,
  SELF_MOCK_PASSPORT,
  ISSUER_PRIVATE_KEY,
  VOUCHER_TTL_SECONDS,
} from "../../config";

// Node.js runtime: the module-level Map must persist across requests, and @selfxyz/core pulls in
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
  /** Human-readable disclosed traits, for the UI to preview before minting. */
  attributes?: {
    nationality: string;
    gender: string;
    olderThan: number;
    ofacClear: boolean;
    nullifier: string;
  };
  vouchers?: SignedForChain[];
  error?: string;
  receivedAt: number;
}

// Keyed by the LOWERCASED recipient address (the proof's `userIdentifier`), so the client can poll
// with the address it already passed as `userId`.
const store = new Map<string, RelayRecord>();

// The disclosures/config the backend enforces MUST line up with the frontend SelfAppBuilder
// disclosures. Base flow: OFAC screening on; age is an optional upgrade proof (see TODO below).
const VERIFICATION_CONFIG: VerificationConfig = { ofac: true };

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
      new DefaultConfigStore(VERIFICATION_CONFIG),
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

  if (!result.isValidDetails.isValid) {
    const record: RelayRecord = {
      status: "error",
      error: "Self proof did not verify (isValid=false).",
      receivedAt: Date.now(),
    };
    const who = result.userData.userIdentifier?.toLowerCase();
    if (who) store.set(who, record);
    return NextResponse.json({ ok: false, error: record.error }, { status: 400 });
  }

  // 2) Map the disclosed attributes to a voucher bound to the proof's own address.
  const to = result.userData.userIdentifier as Address;
  if (!to || !/^0x[0-9a-fA-F]{40}$/.test(to)) {
    return NextResponse.json(
      { ok: false, error: "Proof did not carry a valid hex userIdentifier (the recipient address)." },
      { status: 400 },
    );
  }

  const expiry = BigInt(Math.floor(Date.now() / 1000)) + VOUCHER_TTL_SECONDS;
  const voucher = buildVoucherFromDisclose({ discloseOutput: result.discloseOutput, to, expiry });

  // 3) Sign one voucher per DEPLOYED chain (distinct EIP-712 domain per chain).
  const vouchers: SignedForChain[] = [];
  for (const chain of CHAINS) {
    if (/^0x0{40}$/i.test(chain.pohAddress)) continue; // skip not-yet-deployed chains
    const signature = await signVoucher(ISSUER_PRIVATE_KEY, voucher, chain.chainId, chain.pohAddress);
    vouchers.push({
      chainId: chain.chainId,
      name: chain.name,
      pohAddress: chain.pohAddress,
      voucher: serializeVoucher(voucher),
      signature,
    });
  }

  const record: RelayRecord = {
    status: "ready",
    attributes: {
      nationality: result.discloseOutput.nationality ?? "",
      gender: result.discloseOutput.gender ?? "",
      olderThan: result.discloseOutput.minimumAge ? Number.parseInt(result.discloseOutput.minimumAge, 10) || 0 : 0,
      ofacClear: voucher.ofacClear,
      nullifier: voucher.nullifier.toString(),
    },
    vouchers,
    receivedAt: Date.now(),
  };
  store.set(to.toLowerCase(), record);

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

/** GET /api/self-verify?address=0x… — the client polls for the signed vouchers. */
export async function GET(req: NextRequest) {
  const address = req.nextUrl.searchParams.get("address")?.toLowerCase();
  if (!address) {
    return NextResponse.json({ ok: false, error: "Missing `address` query param." }, { status: 400 });
  }
  const record = store.get(address);
  if (!record) return NextResponse.json({ status: "pending" });
  return NextResponse.json(record);
}

/** DELETE /api/self-verify?address=0x… — drop a consumed record so it cannot be reused. */
export async function DELETE(req: NextRequest) {
  const address = req.nextUrl.searchParams.get("address")?.toLowerCase();
  if (address) store.delete(address);
  return NextResponse.json({ ok: true });
}
