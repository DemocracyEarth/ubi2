/**
 * Testnet-only gas sponsorship for a verified v1 Proof-of-Humanity voucher.
 *
 * The browser chooses only `chainId`. Recipient, proof, voucher and issuer signature are loaded
 * from the 128-bit address/session capability created by the Self callback. The isolated sponsor
 * key signs only the transaction envelope; it never signs credentials and never crosses this
 * server-only module boundary.
 */

import { NextRequest, NextResponse } from "next/server";
import type { Address } from "viem";
import { QUICK_LAUNCH_CHAINS } from "../../quick-launch";
import { getSponsoredMintServerConfig, type SponsoredMintServerConfig } from "../../server-config";
import {
  sponsoredMintAttemptEvidence,
  validateSponsoredMintBinding,
  type SponsoredMintAttempt,
} from "../../lib/sponsored-mint";
import {
  compareAndUpdateVerificationRecord,
  getVerificationRecord,
  rateLimit,
  updateVerificationRecord,
} from "../../lib/server/verification-store";
import { verificationCapability } from "../../lib/server/verification-capability";
import {
  readSponsoredMintEvidence,
  SponsoredMintExecutionError,
  submitSponsoredMint,
  waitForSponsoredMintEvidence,
  type SponsoredMintExecutionInput,
} from "../../lib/server/sponsored-mint-executor";
import type { RelayRecord } from "../../lib/verification-record";

export const runtime = "nodejs";

const MAX_ATTEMPTS_PER_CHAIN = 3;
const RETRY_DELAY_MS = 60_000;

function noStoreHeaders(extra?: Record<string, string>): Record<string, string> {
  return { "cache-control": "no-store", ...extra };
}

function safeSource(req: NextRequest): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "sponsored-mint";
}

function requestedChain(req: NextRequest) {
  const raw = req.nextUrl.searchParams.get("chainId");
  if (!raw || !/^[1-9][0-9]*$/.test(raw)) return null;
  const chainId = Number(raw);
  if (!Number.isSafeInteger(chainId)) return null;
  return QUICK_LAUNCH_CHAINS.find((chain) => chain.chainId === chainId) ?? null;
}

function loadConfig(): SponsoredMintServerConfig | null {
  try {
    return getSponsoredMintServerConfig();
  } catch {
    return null;
  }
}

function replaceAttempt(
  address: Address,
  session: string,
  chainId: number,
  attempt: SponsoredMintAttempt,
): boolean {
  const latest = getVerificationRecord<RelayRecord>(address, session);
  if (!latest) return false;
  return updateVerificationRecord(address, session, {
    ...latest,
    sponsoredMints: { ...latest.sponsoredMints, [String(chainId)]: attempt },
  });
}

function safeError(code: string): { status: number; message: string } {
  switch (code) {
    case "policy-disabled":
      return { status: 403, message: "Sponsored minting is not enabled for this testnet." };
    case "sponsor-balance":
      return { status: 503, message: "The testnet sponsor pool is temporarily out of funds." };
    case "fee-limit":
    case "gas-limit":
      return { status: 503, message: "Current testnet fees exceed the sponsorship safety limit." };
    case "simulation-rejected":
      return { status: 409, message: "This proof-bound voucher cannot be sponsored in its current state." };
    case "voucher-expired":
      return { status: 410, message: "The voucher is no longer fresh; verify with Self again." };
    case "issuer-mismatch":
    case "contract-mismatch":
    case "chain-mismatch":
    case "signer-role-overlap":
      return { status: 503, message: "The sponsor safety configuration did not pass its live checks." };
    case "transaction-reverted":
    case "receipt-mismatch":
      return { status: 502, message: "The sponsor transaction did not produce valid mint receipt evidence." };
    case "attempt-limit":
      return { status: 429, message: "This verification session reached its sponsorship attempt limit." };
    case "rate-limit":
      return { status: 429, message: "Too many sponsorship requests. Try again after the retry window." };
    default:
      return { status: 503, message: "Testnet sponsorship is temporarily unavailable." };
  }
}

function errorResponse(code: string, retryAfter?: number) {
  const safe = safeError(code);
  return NextResponse.json(
    { ok: false, code, error: safe.message },
    {
      status: safe.status,
      headers: noStoreHeaders(retryAfter ? { "retry-after": String(retryAfter) } : undefined),
    },
  );
}

function pendingResponse(
  attempt: SponsoredMintAttempt,
  chain: NonNullable<ReturnType<typeof requestedChain>>,
  recipient: Address,
) {
  return NextResponse.json(
    {
      ok: true,
      status: attempt.status,
      evidence: sponsoredMintAttemptEvidence(attempt, chain, recipient),
    },
    { status: 202, headers: noStoreHeaders({ "retry-after": "3" }) },
  );
}

interface BoundRequest {
  address: Address;
  session: string;
  chain: NonNullable<ReturnType<typeof requestedChain>>;
  record: RelayRecord;
  execution: SponsoredMintExecutionInput;
}

function bindRequest(req: NextRequest): BoundRequest | NextResponse {
  const capability = verificationCapability(req);
  const chain = requestedChain(req);
  if (!capability || !chain) {
    return NextResponse.json(
      { ok: false, error: "A valid address, 128-bit session, and configured chainId are required." },
      { status: 400, headers: noStoreHeaders() },
    );
  }
  const record = getVerificationRecord<RelayRecord>(capability.address, capability.session);
  if (!record) {
    return NextResponse.json(
      { ok: false, error: "The verified session expired; verify with Self again." },
      { status: 410, headers: noStoreHeaders() },
    );
  }
  if (record.status !== "ready" || !record.proof || !record.vouchers) {
    return NextResponse.json(
      { ok: false, error: "This session does not contain a sponsor-eligible v1 voucher." },
      { status: 409, headers: noStoreHeaders() },
    );
  }
  const signed = record.vouchers.find((voucher) => voucher.chainId === chain.chainId);
  if (!signed) return errorResponse("policy-disabled");
  let voucher;
  try {
    voucher = validateSponsoredMintBinding({
      capabilityAddress: capability.address,
      chain,
      signed,
      proof: record.proof,
    });
  } catch {
    return NextResponse.json(
      { ok: false, error: "The verification capability and stored voucher do not match." },
      { status: 403, headers: noStoreHeaders() },
    );
  }
  const config = loadConfig();
  if (!config || !config.enabledChainIds.includes(chain.chainId)) return errorResponse("policy-disabled");
  return {
    address: capability.address,
    session: capability.session,
    chain,
    record,
    execution: { chain, voucher, signature: signed.signature, config },
  };
}

async function resolveSubmitted(bound: BoundRequest, attempt: Extract<SponsoredMintAttempt, { status: "submitted" }>) {
  try {
    const evidence = await readSponsoredMintEvidence(bound.execution, attempt.transactionHash);
    if (!evidence) return pendingResponse(attempt, bound.chain, bound.address);
    const confirmed: SponsoredMintAttempt = { status: "confirmed", attempts: attempt.attempts, evidence };
    replaceAttempt(bound.address, bound.session, bound.chain.chainId, confirmed);
    return NextResponse.json({ ok: true, status: "confirmed", evidence }, { headers: noStoreHeaders() });
  } catch (error) {
    if (error instanceof SponsoredMintExecutionError && error.terminal) {
      const failed: SponsoredMintAttempt = {
        status: "failed",
        attempts: attempt.attempts,
        failedAt: Date.now(),
        retryAfter: Number.MAX_SAFE_INTEGER,
        code: error.code,
      };
      replaceAttempt(bound.address, bound.session, bound.chain.chainId, failed);
      return errorResponse(error.code);
    }
    return pendingResponse(attempt, bound.chain, bound.address);
  }
}

/** GET recovers idempotent submitted/confirmed evidence without ever issuing another transaction. */
export async function GET(req: NextRequest) {
  const sourceLimit = rateLimit("sponsored-mint-status-source", safeSource(req), 120, 60);
  if (!sourceLimit.allowed) return errorResponse("rate-limit", sourceLimit.retryAfter);
  const bound = bindRequest(req);
  if (bound instanceof NextResponse) return bound;
  const attempt = bound.record.sponsoredMints?.[String(bound.chain.chainId)];
  if (!attempt) {
    return NextResponse.json({ ok: true, status: "not-started", evidence: null }, { headers: noStoreHeaders() });
  }
  if (attempt.status === "confirmed") {
    return NextResponse.json(
      { ok: true, status: "confirmed", evidence: attempt.evidence },
      { headers: noStoreHeaders() },
    );
  }
  if (attempt.status === "submitted") return resolveSubmitted(bound, attempt);
  if (attempt.status === "submitting") return pendingResponse(attempt, bound.chain, bound.address);
  return errorResponse(
    attempt.code,
    attempt.retryAfter === Number.MAX_SAFE_INTEGER
      ? undefined
      : Math.max(1, Math.ceil((attempt.retryAfter - Date.now()) / 1_000)),
  );
}

/** POST consumes one sponsorship attempt. No body is accepted; all mint inputs are server-held. */
export async function POST(req: NextRequest) {
  if (req.body !== null) {
    return NextResponse.json(
      { ok: false, error: "Sponsored mint requests do not accept a body." },
      { status: 400, headers: noStoreHeaders() },
    );
  }
  const sourceLimit = rateLimit("sponsored-mint-source", safeSource(req), 30, 60);
  if (!sourceLimit.allowed) return errorResponse("rate-limit", sourceLimit.retryAfter);
  const bound = bindRequest(req);
  if (bound instanceof NextResponse) return bound;

  const existing = bound.record.sponsoredMints?.[String(bound.chain.chainId)];
  if (existing?.status === "confirmed") {
    return NextResponse.json(
      { ok: true, status: "confirmed", evidence: existing.evidence },
      { headers: noStoreHeaders() },
    );
  }
  if (existing?.status === "submitted") return resolveSubmitted(bound, existing);
  if (existing?.status === "submitting") return pendingResponse(existing, bound.chain, bound.address);
  if (existing?.status === "failed" && Date.now() < existing.retryAfter) {
    return errorResponse(existing.code, Math.max(1, Math.ceil((existing.retryAfter - Date.now()) / 1_000)));
  }

  const attempts = (existing?.attempts ?? 0) + 1;
  if (attempts > MAX_ATTEMPTS_PER_CHAIN) return errorResponse("attempt-limit", 600);
  const capabilityLimit = rateLimit(
    "sponsored-mint-capability",
    `${bound.address}:${bound.session}`,
    10,
    10 * 60,
  );
  const accountLimit = rateLimit("sponsored-mint-account", bound.address, 12, 24 * 60 * 60);
  const chainBudget = rateLimit(
    "sponsored-mint-chain-budget",
    String(bound.chain.chainId),
    bound.execution.config.dailyTransactionLimit,
    24 * 60 * 60,
  );
  if (!capabilityLimit.allowed || !accountLimit.allowed || !chainBudget.allowed) {
    return errorResponse(
      "rate-limit",
      Math.max(capabilityLimit.retryAfter, accountLimit.retryAfter, chainBudget.retryAfter),
    );
  }

  const startedAt = Date.now();
  const submitting: SponsoredMintAttempt = { status: "submitting", attempts, startedAt };
  const claimed = compareAndUpdateVerificationRecord(bound.address, bound.session, bound.record, {
    ...bound.record,
    sponsoredMints: { ...bound.record.sponsoredMints, [String(bound.chain.chainId)]: submitting },
  });
  if (!claimed) {
    const latest = getVerificationRecord<RelayRecord>(bound.address, bound.session);
    if (!latest) {
      return NextResponse.json(
        { ok: false, error: "The verified session expired; verify with Self again." },
        { status: 410, headers: noStoreHeaders() },
      );
    }
    const raced = latest.sponsoredMints?.[String(bound.chain.chainId)];
    if (raced?.status === "confirmed") {
      return NextResponse.json(
        { ok: true, status: "confirmed", evidence: raced.evidence },
        { headers: noStoreHeaders() },
      );
    }
    if (raced?.status === "submitted") return resolveSubmitted({ ...bound, record: latest }, raced);
    if (raced?.status === "submitting") return pendingResponse(raced, bound.chain, bound.address);
    return NextResponse.json(
      { ok: false, error: "The sponsorship state changed; retry to recover its current status." },
      { status: 409, headers: noStoreHeaders({ "retry-after": "1" }) },
    );
  }

  let submitted: Extract<SponsoredMintAttempt, { status: "submitted" }>;
  try {
    const result = await submitSponsoredMint(bound.execution);
    submitted = {
      status: "submitted",
      attempts,
      startedAt,
      transactionHash: result.transactionHash,
      submittedAt: result.submittedAt,
    };
    if (!replaceAttempt(bound.address, bound.session, bound.chain.chainId, submitted)) {
      return pendingResponse(submitted, bound.chain, bound.address);
    }
  } catch (error) {
    const code = error instanceof SponsoredMintExecutionError ? error.code : "sponsor-unavailable";
    const terminal = error instanceof SponsoredMintExecutionError && error.terminal;
    const failed: SponsoredMintAttempt = {
      status: "failed",
      attempts,
      failedAt: Date.now(),
      retryAfter: terminal ? Number.MAX_SAFE_INTEGER : Date.now() + RETRY_DELAY_MS,
      code,
    };
    replaceAttempt(bound.address, bound.session, bound.chain.chainId, failed);
    return errorResponse(code, terminal ? undefined : Math.ceil(RETRY_DELAY_MS / 1_000));
  }

  try {
    const evidence = await waitForSponsoredMintEvidence(bound.execution, submitted.transactionHash);
    const confirmed: SponsoredMintAttempt = { status: "confirmed", attempts, evidence };
    replaceAttempt(bound.address, bound.session, bound.chain.chainId, confirmed);
    return NextResponse.json({ ok: true, status: "confirmed", evidence }, { headers: noStoreHeaders() });
  } catch (error) {
    if (error instanceof SponsoredMintExecutionError && error.terminal) {
      const failed: SponsoredMintAttempt = {
        status: "failed",
        attempts,
        failedAt: Date.now(),
        retryAfter: Number.MAX_SAFE_INTEGER,
        code: error.code,
      };
      replaceAttempt(bound.address, bound.session, bound.chain.chainId, failed);
      return errorResponse(error.code);
    }
    return pendingResponse(submitted, bound.chain, bound.address);
  }
}
