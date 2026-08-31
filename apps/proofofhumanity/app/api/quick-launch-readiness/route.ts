import { NextResponse } from "next/server";
import { quickLaunchHostReadiness } from "../../lib/server/quick-launch-host-readiness";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Public, transaction-free readiness facts. No secret value or secret-manager path crosses this boundary. */
export async function GET() {
  const readiness = quickLaunchHostReadiness();
  return NextResponse.json(readiness, {
    status: readiness.ready ? 200 : 503,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
