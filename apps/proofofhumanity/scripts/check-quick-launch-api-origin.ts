import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { QUICK_LAUNCH_API_RUNTIME } from "../app/quick-launch-api-runtime";
import {
  QUICK_LAUNCH_HOST_BLOCKERS,
  QUICK_LAUNCH_HOST_READINESS_SCHEMA,
  isSha256,
  isSourceRevision,
} from "../app/quick-launch-host";
import { QUICK_LAUNCH_RELEASE } from "../app/quick-launch";
import { parseQuickLaunchApiOrigin } from "../quick-launch-proxy.mjs";

const EVIDENCE_SCHEMA = "org.proofofhumanity.quick-launch.api-origin-evidence/1";
const HEALTH_SCHEMA = "org.proofofhumanity.quick-launch.api-health/1";
const HEALTH_FIELDS = [
  "schema",
  "ok",
  "release",
  "chainId",
  "apiRuntime",
  "transactionFree",
  "sourceRevision",
  "bootId",
  "startedAt",
].sort();
const READINESS_FIELDS = [
  "schema",
  "release",
  "transactionFree",
  "chainId",
  "canonicalOrigin",
  "sourceRevision",
  "selfEndpoint",
  "selfEnvironment",
  "apiRuntime",
  "blockchainTransactionsEnabled",
  "singleStickyNodeDeclared",
  "topologyAttestationSha256",
  "issuerSecretAttestationSha256",
  "issuerAddress",
  "sponsorSecretAttestationSha256",
  "sponsorAddress",
  "sponsorEnabledChainIds",
  "sponsorPolicyValid",
  "ready",
  "blockers",
].sort();
const HOST_BLOCKERS = new Set<string>(QUICK_LAUNCH_HOST_BLOCKERS);

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function exactFields(value: Record<string, unknown>, expected: string[]): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected);
}

function isoTimestamp(value: unknown): string | null {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) return null;
  return new Date(value).toISOString() === value ? value : null;
}

function parseJson(text: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(text) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function sanitizeHealth(value: Record<string, unknown> | null) {
  if (!value) return null;
  return {
    fieldsAllowlisted: exactFields(value, HEALTH_FIELDS),
    schema: value.schema === HEALTH_SCHEMA ? value.schema : null,
    ok: value.ok === true,
    release: value.release === QUICK_LAUNCH_RELEASE.id ? value.release : null,
    chainId: value.chainId === QUICK_LAUNCH_RELEASE.chainId ? value.chainId : null,
    apiRuntime: value.apiRuntime === QUICK_LAUNCH_API_RUNTIME ? value.apiRuntime : null,
    transactionFree: value.transactionFree === true,
    sourceRevision:
      typeof value.sourceRevision === "string" && isSourceRevision(value.sourceRevision)
        ? value.sourceRevision
        : null,
    bootId:
      typeof value.bootId === "string" && /^[0-9a-f]{8}-[0-9a-f-]{27}$/u.test(value.bootId)
        ? value.bootId
        : null,
    startedAt: isoTimestamp(value.startedAt),
  };
}

function sanitizeReadiness(value: Record<string, unknown> | null) {
  if (!value) return null;
  const blockers = Array.isArray(value.blockers)
    ? value.blockers.filter((item): item is string => typeof item === "string" && HOST_BLOCKERS.has(item))
    : [];
  return {
    fieldsAllowlisted: exactFields(value, READINESS_FIELDS),
    schema: value.schema === QUICK_LAUNCH_HOST_READINESS_SCHEMA ? value.schema : null,
    ready: value.ready === true,
    transactionFree: value.transactionFree === true,
    apiRuntime: value.apiRuntime === QUICK_LAUNCH_API_RUNTIME ? value.apiRuntime : null,
    blockchainTransactionsEnabled: value.blockchainTransactionsEnabled === true,
    sourceRevision:
      typeof value.sourceRevision === "string" && isSourceRevision(value.sourceRevision)
        ? value.sourceRevision
        : null,
    topologyAttestationSha256:
      typeof value.topologyAttestationSha256 === "string" && isSha256(value.topologyAttestationSha256)
        ? value.topologyAttestationSha256
        : null,
    issuerSecretAttestationSha256:
      typeof value.issuerSecretAttestationSha256 === "string" && isSha256(value.issuerSecretAttestationSha256)
        ? value.issuerSecretAttestationSha256
        : null,
    sponsorSecretAttestationSha256:
      typeof value.sponsorSecretAttestationSha256 === "string" && isSha256(value.sponsorSecretAttestationSha256)
        ? value.sponsorSecretAttestationSha256
        : null,
    blockers,
  };
}

function priorHealth(path: string | undefined) {
  if (!path) return null;
  const parsed = parseJson(readFileSync(path, "utf8"));
  if (parsed?.schema !== EVIDENCE_SCHEMA || parsed.phase !== "before") return null;
  const directOrigin = parsed.directOrigin;
  if (!directOrigin || typeof directOrigin !== "object" || Array.isArray(directOrigin)) return null;
  const health = (directOrigin as Record<string, unknown>).health;
  if (!health || typeof health !== "object" || Array.isArray(health)) return null;
  const record = (health as Record<string, unknown>).record;
  return record && typeof record === "object" && !Array.isArray(record)
    ? (record as Record<string, unknown>)
    : null;
}

async function main(): Promise<void> {
  const blockers: string[] = [];
  const phase = process.env.QUICK_LAUNCH_API_EVIDENCE_PHASE?.trim();
  if (phase !== "before" && phase !== "after") {
    throw new Error("QUICK_LAUNCH_API_EVIDENCE_PHASE must be exactly before or after.");
  }

  const originText = parseQuickLaunchApiOrigin(process.env.QUICK_LAUNCH_API_ORIGIN);
  if (!originText) throw new Error("QUICK_LAUNCH_API_ORIGIN is required.");
  const origin = new URL(originText);

  const expectedRevision = process.env.QUICK_LAUNCH_EXPECTED_SOURCE_REVISION?.trim().toLowerCase() ?? null;
  if (!isSourceRevision(expectedRevision)) blockers.push("expected-source-revision-missing");

  const [healthResponse, readinessResponse] = await Promise.all([
    fetch(new URL("/api/healthz", origin), {
      redirect: "error",
      headers: { accept: "application/json", "cache-control": "no-cache" },
    }),
    fetch(new URL("/api/quick-launch-readiness", origin), {
      redirect: "error",
      headers: { accept: "application/json", "cache-control": "no-cache" },
    }),
  ]);
  const [healthText, readinessText] = await Promise.all([healthResponse.text(), readinessResponse.text()]);
  const health = sanitizeHealth(parseJson(healthText));
  const readiness = sanitizeReadiness(parseJson(readinessText));

  if (healthResponse.status !== 200) blockers.push("health-not-200");
  if (!health) blockers.push("health-not-json-object");
  else {
    if (!health.fieldsAllowlisted) blockers.push("health-fields-not-allowlisted");
    if (!health.ok || !health.transactionFree) blockers.push("health-not-transaction-free");
    if (health.apiRuntime !== QUICK_LAUNCH_API_RUNTIME) blockers.push("health-runtime-mismatch");
    if (expectedRevision && health.sourceRevision !== expectedRevision) blockers.push("health-revision-mismatch");
    if (!health.bootId || !health.startedAt) blockers.push("health-process-identity-missing");
  }
  if (readinessResponse.status !== 200) blockers.push("readiness-not-200");
  if (!readiness) blockers.push("readiness-not-json-object");
  else {
    if (!readiness.fieldsAllowlisted) blockers.push("readiness-fields-not-allowlisted");
    if (!readiness.ready) blockers.push("readiness-not-ready");
    if (!readiness.transactionFree || readiness.blockchainTransactionsEnabled) {
      blockers.push("readiness-not-transaction-free");
    }
    if (expectedRevision && readiness.sourceRevision !== expectedRevision) {
      blockers.push("readiness-revision-mismatch");
    }
  }

  let restartVerified: boolean | null = null;
  if (phase === "after") {
    const prior = priorHealth(process.env.QUICK_LAUNCH_BEFORE_EVIDENCE_PATH?.trim());
    if (!prior) {
      blockers.push("before-restart-evidence-missing");
      restartVerified = false;
    } else if (
      !health ||
      typeof prior.bootId !== "string" ||
      prior.bootId === health.bootId ||
      prior.sourceRevision !== health.sourceRevision ||
      typeof prior.startedAt !== "string" ||
      !health.startedAt ||
      Date.parse(health.startedAt) <= Date.parse(prior.startedAt)
    ) {
      blockers.push("restart-process-transition-not-proven");
      restartVerified = false;
    } else {
      restartVerified = true;
    }
  }

  const transactionFree =
    health?.transactionFree === true &&
    readiness?.transactionFree === true &&
    readiness.blockchainTransactionsEnabled === false;
  const evidence = {
    schema: EVIDENCE_SCHEMA,
    phase,
    observedAt: new Date().toISOString(),
    transactionFree,
    directOrigin: {
      origin: origin.origin,
      health: {
        status: healthResponse.status,
        responseSha256: sha256(healthText),
        record: health,
      },
      readiness: {
        status: readinessResponse.status,
        responseSha256: sha256(readinessText),
        record: readiness,
      },
    },
    restartVerified,
    ready: blockers.length === 0,
    blockers: [...new Set(blockers)].sort(),
  };
  console.log(JSON.stringify(evidence, null, 2));
  if (!evidence.ready) process.exitCode = 1;
}

void main();
