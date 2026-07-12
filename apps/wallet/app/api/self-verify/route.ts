/**
 * M6 Stage C1 — the ubi2 Self relay endpoint (spec 06b §5.2).
 *
 * A thin, UNTRUSTED encoder. This route is what the Self app's `SelfAppBuilder({ endpoint })`
 * points at. When a user completes an in-app verification, the Self app POSTs
 * `{ attestationId, proof, publicSignals, userContextData }` here. This handler:
 *
 *   1. shape-checks the payload (arity-21 `publicSignals`, a well-formed `proof` object) —
 *      `@ubi2/sdk`'s `validateSelfRelayPayload`, the SAME validator the paste-bundle path uses;
 *   2. ABI-encodes `submitZkPassportProof(bytes,bytes32[21],uint8)` calldata — `@ubi2/sdk`'s
 *      `encodeSelfRelayPayload` (selector 0xf342a2f3), reusing the C0 encoders verbatim;
 *   3. stores the result keyed by the submitter address embedded in the proof itself
 *      (`publicSignals[20]`, spec §4.1) so the wallet can poll for it and submit via MetaMask.
 *
 * TRUST BOUNDARY (spec §5.2, load-bearing): this relay NEVER decides validity. It does not run
 * the Groth16 pairing, does not check Self-root membership, does not check freshness — none of
 * that is possible client-side without the pinned VK and the live on-chain root set. The ubi2
 * runtime (`crates/zkpoh` + `crates/runtime::submit_zk_passport_proof`) re-verifies the proof and
 * re-binds every public-input slot from scratch on submission (spec §4.4). A relay that lies —
 * garbles a signal, swaps a proof — can at worst produce a transaction the chain rejects
 * fail-closed (`InvalidProof` / a slot-mismatch error, EC-F-C3). This endpoint is not, and must
 * never become, part of the chain's trust base.
 *
 * STORAGE CAVEAT (devnet/demo): the store below is an in-process `Map`, which is fine for a
 * single `next dev`/`next start` worker but is NOT durable across restarts or multiple server
 * instances. A production relay needs a shared store (Redis, a DB row, or a KV binding) — noted
 * here rather than silently assumed.
 *
 * REACHABILITY CAVEAT (spec §5.1, honest note): the Self app runs on a phone. `SelfAppBuilder`
 * refuses `localhost`/`127.0.0.1` endpoints outright (enforced by `@selfxyz/sdk-common`), so a
 * real end-to-end run needs this route to be publicly reachable — a tunnel (ngrok/cloudflared)
 * during dev, or a deployed relay in production. `NEXT_PUBLIC_SELF_ENDPOINT` in `app/config.ts`
 * is where that public URL is configured; see `apps/wallet/docs/self-verification-flow.md`.
 */

import { NextRequest, NextResponse } from "next/server";
import {
  validateSelfRelayPayload,
  encodeSelfRelayPayload,
  extractNullifier,
  extractSubmitterAddress,
  type SelfRelayPayload,
} from "@ubi2/sdk";
import { captureRawBundle } from "./capture";

// Force the Node.js runtime (not edge) so the module-level Map persists across requests within
// this worker process.
export const runtime = "nodejs";

interface RelayRecord {
  status: "ready" | "error";
  calldata?: `0x${string}`;
  nullifier?: string;
  submitter?: string;
  attestationId?: number | string;
  error?: string;
  receivedAt: number;
}

// In-process store keyed by the LOWERCASED submitter address embedded in the proof itself
// (publicSignals[20], spec §4.1) — not by userContextData, so a client can poll using only the
// address it already knows (the one it passed as `userId` to SelfAppBuilder), independent of
// whatever the Self app echoes back.
const store = new Map<string, RelayRecord>();

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body." }, { status: 400 });
  }

  const shapeErr = validateSelfRelayPayload(body);
  if (shapeErr) {
    return NextResponse.json({ ok: false, error: shapeErr }, { status: 400 });
  }

  const payload = body as SelfRelayPayload;

  let submitter: string;
  let nullifier: string;
  let calldata: `0x${string}`;
  try {
    const bundle = { proof: payload.proof, publicSignals: payload.publicSignals };
    submitter = extractSubmitterAddress(bundle).toLowerCase();
    nullifier = extractNullifier(bundle);
    calldata = encodeSelfRelayPayload(payload);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ ok: false, error: `Encoding failed: ${msg}` }, { status: 400 });
  }

  // Advisory cross-check only (never a trust boundary — see the file header): if userContextData
  // was supplied, note whether it looks like it echoes the same address. A mismatch is NOT
  // rejected here; the runtime's on-chain `user_identifier == tx sender` bind (§4.4 step 4) is
  // the only check that matters.
  const contextNote =
    payload.userContextData &&
    !payload.userContextData.toLowerCase().includes(submitter.slice(2))
      ? "userContextData does not obviously echo the proof's embedded address (advisory only; the on-chain bind is authoritative)."
      : undefined;

  const record: RelayRecord = {
    status: "ready",
    calldata,
    nullifier,
    submitter,
    attestationId: payload.attestationId,
    receivedAt: Date.now(),
  };
  store.set(submitter, record);

  // EC-C7 capture side-channel: a NO-OP unless UBI2_SELF_CAPTURE_DIR is set (dev-only). Persists the
  // raw {proof, publicSignals} + decoded reconciliation values to disk; never affects validity.
  const capturedTo = captureRawBundle(payload, submitter);

  return NextResponse.json({
    ok: true,
    submitter,
    nullifier,
    note: contextNote,
    ...(capturedTo ? { captured: capturedTo } : {}),
  });
}

/**
 * GET /api/self-verify?address=0x... — the wallet polls this after rendering the QR/deeplink to
 * discover the encoded calldata once the Self app has POSTed the proof.
 */
export async function GET(req: NextRequest) {
  const address = req.nextUrl.searchParams.get("address")?.toLowerCase();
  if (!address) {
    return NextResponse.json({ ok: false, error: "Missing `address` query param." }, { status: 400 });
  }
  const record = store.get(address);
  if (!record) {
    return NextResponse.json({ status: "pending" });
  }
  return NextResponse.json(record);
}

/**
 * DELETE /api/self-verify?address=0x... — clear a consumed record (e.g. after the wallet has
 * submitted the calldata on-chain), so a stale entry cannot be polled twice.
 */
export async function DELETE(req: NextRequest) {
  const address = req.nextUrl.searchParams.get("address")?.toLowerCase();
  if (address) store.delete(address);
  return NextResponse.json({ ok: true });
}
