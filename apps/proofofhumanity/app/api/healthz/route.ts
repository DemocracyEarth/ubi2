import { NextResponse } from "next/server";
import { quickLaunchApiHealth } from "../../lib/server/quick-launch-api-health";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Process-only health for the dedicated origin. The Amplify frontend does not proxy this path. */
export async function GET() {
  const health = quickLaunchApiHealth();
  return NextResponse.json(health, {
    status: health.ok ? 200 : 503,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}
