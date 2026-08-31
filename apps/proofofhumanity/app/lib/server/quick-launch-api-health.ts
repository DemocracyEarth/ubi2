import "server-only";

import { randomUUID } from "node:crypto";
import { QUICK_LAUNCH_RELEASE } from "../../quick-launch";
import {
  QUICK_LAUNCH_API_RUNTIME,
  assessQuickLaunchApiRuntime,
} from "../../quick-launch-api-runtime";
import { isSourceRevision } from "../../quick-launch-host";

const bootId = randomUUID();
const startedAt = new Date().toISOString();

function sourceRevision(env: NodeJS.ProcessEnv): string | null {
  const candidate = (env.POH_SOURCE_REVISION ?? env.AWS_COMMIT_ID ?? "").trim().toLowerCase();
  return isSourceRevision(candidate) ? candidate : null;
}

/**
 * A public allowlisted process probe for load-balancer health and restart drills. It intentionally
 * contains no environment dump, secret reference, signer address, request data, or RPC URL.
 */
export function quickLaunchApiHealth(env: NodeJS.ProcessEnv = process.env) {
  const runtime = assessQuickLaunchApiRuntime(env);
  const revision = sourceRevision(env);
  return {
    schema: "org.proofofhumanity.quick-launch.api-health/1" as const,
    ok: runtime.dedicatedSingleReplica && runtime.transactionFree && revision !== null,
    release: QUICK_LAUNCH_RELEASE.id,
    chainId: QUICK_LAUNCH_RELEASE.chainId,
    apiRuntime: runtime.dedicatedSingleReplica ? QUICK_LAUNCH_API_RUNTIME : null,
    transactionFree: runtime.transactionFree,
    sourceRevision: revision,
    bootId,
    startedAt,
  };
}
