import "server-only";

import { NextResponse } from "next/server";
import {
  QUICK_LAUNCH_TRANSACTIONS_DISABLED_CODE,
  assessQuickLaunchApiRuntime,
} from "../../quick-launch-api-runtime";

const NO_STORE_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
} as const;

/** Return a public, constant failure before request parsing, key access, RPC work, or state mutation. */
export function requireDedicatedQuickLaunchApiOrigin(
  env: NodeJS.ProcessEnv = process.env,
): NextResponse | null {
  if (assessQuickLaunchApiRuntime(env).dedicatedSingleReplica) return null;
  return NextResponse.json(
    {
      ok: false,
      code: "dedicated-api-origin-required",
      error: "Quick Launch API requests are accepted only by the dedicated single-replica service.",
    },
    { status: 503, headers: NO_STORE_HEADERS },
  );
}
/** The release-candidate origin is deliberately read/sign-only until a later transaction gate. */
export function requireBlockchainTransactionsEnabled(
  env: NodeJS.ProcessEnv = process.env,
): NextResponse | null {
  if (!assessQuickLaunchApiRuntime(env).transactionFree) return null;
  return NextResponse.json(
    {
      ok: false,
      code: QUICK_LAUNCH_TRANSACTIONS_DISABLED_CODE,
      error: "Blockchain transactions are disabled on this release-candidate API origin.",
    },
    { status: 503, headers: NO_STORE_HEADERS },
  );
}
