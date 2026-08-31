import { createHash } from "node:crypto";
import { isAddress, type Address } from "viem";
import {
  QUICK_LAUNCH_HOST_BLOCKERS,
  QUICK_LAUNCH_HOST_READINESS_SCHEMA,
  isSha256,
  isSourceRevision,
  type QuickLaunchHostBlocker,
} from "../app/quick-launch-host";
import { QUICK_LAUNCH_RELEASE } from "../app/quick-launch";

const EVIDENCE_SCHEMA = "org.proofofhumanity.quick-launch.host-preflight-evidence/1";
const FORBIDDEN_RELEASE_MARKERS = ["Ethereum Sepolia", "Celo Sepolia", "World Chain Sepolia", "Rootstock Testnet"];
const KNOWN_HOST_BLOCKERS = new Set<string>(QUICK_LAUNCH_HOST_BLOCKERS);

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function expectedDigest(name: string, blocker: string, blockers: string[]): string | null {
  const value = process.env[name]?.trim().toLowerCase() ?? null;
  if (!isSha256(value)) {
    blockers.push(blocker);
    return null;
  }
  return value;
}

function addressOrNull(value: unknown): Address | null {
  return typeof value === "string" && isAddress(value) ? value : null;
}

function integers(value: unknown): number[] {
  return Array.isArray(value) && value.every((item) => Number.isSafeInteger(item)) ? (value as number[]) : [];
}

function sanitizeHostRecord(value: unknown) {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const observedBlockers = Array.isArray(record.blockers)
    ? record.blockers.filter((item): item is QuickLaunchHostBlocker => typeof item === "string" && KNOWN_HOST_BLOCKERS.has(item))
    : [];
  return {
    schema: record.schema === QUICK_LAUNCH_HOST_READINESS_SCHEMA ? record.schema : null,
    release: record.release === QUICK_LAUNCH_RELEASE.id ? record.release : null,
    transactionFree: record.transactionFree === true,
    chainId: Number.isSafeInteger(record.chainId) ? record.chainId : null,
    canonicalOrigin:
      record.canonicalOrigin === QUICK_LAUNCH_RELEASE.canonicalOrigin ? record.canonicalOrigin : null,
    sourceRevision:
      typeof record.sourceRevision === "string" && isSourceRevision(record.sourceRevision)
        ? record.sourceRevision
        : null,
    selfEndpoint:
      record.selfEndpoint === QUICK_LAUNCH_RELEASE.canonicalSelfEndpoint ? record.selfEndpoint : null,
    selfEnvironment:
      record.selfEnvironment === "staging" || record.selfEnvironment === "production"
        ? record.selfEnvironment
        : null,
    apiRuntime: record.apiRuntime === "dedicated-single-replica" ? record.apiRuntime : null,
    blockchainTransactionsEnabled: record.blockchainTransactionsEnabled === true,
    singleStickyNodeDeclared: record.singleStickyNodeDeclared === true,
    topologyAttestationSha256:
      typeof record.topologyAttestationSha256 === "string" && isSha256(record.topologyAttestationSha256)
        ? record.topologyAttestationSha256
        : null,
    issuerSecretAttestationSha256:
      typeof record.issuerSecretAttestationSha256 === "string" && isSha256(record.issuerSecretAttestationSha256)
        ? record.issuerSecretAttestationSha256
        : null,
    issuerAddress: addressOrNull(record.issuerAddress),
    sponsorSecretAttestationSha256:
      typeof record.sponsorSecretAttestationSha256 === "string" && isSha256(record.sponsorSecretAttestationSha256)
        ? record.sponsorSecretAttestationSha256
        : null,
    sponsorAddress: addressOrNull(record.sponsorAddress),
    sponsorEnabledChainIds: integers(record.sponsorEnabledChainIds),
    sponsorPolicyValid: record.sponsorPolicyValid === true,
    ready: record.ready === true,
    blockers: observedBlockers,
  };
}

async function main(): Promise<void> {
  const blockers: string[] = [];
  const originText = process.env.QUICK_LAUNCH_HOST_ORIGIN?.trim() || QUICK_LAUNCH_RELEASE.canonicalOrigin;
  let origin: URL;
  try {
    origin = new URL(originText);
  } catch {
    throw new Error("QUICK_LAUNCH_HOST_ORIGIN must be an absolute URL.");
  }
  if (origin.origin !== QUICK_LAUNCH_RELEASE.canonicalOrigin || origin.pathname !== "/") {
    throw new Error(`QUICK_LAUNCH_HOST_ORIGIN must be exactly ${QUICK_LAUNCH_RELEASE.canonicalOrigin}.`);
  }

  const expectedSourceRevision = process.env.QUICK_LAUNCH_EXPECTED_SOURCE_REVISION?.trim().toLowerCase() ?? null;
  if (!isSourceRevision(expectedSourceRevision)) blockers.push("expected-source-revision-missing");
  const expectedTopologyAttestation = expectedDigest(
    "QUICK_LAUNCH_EXPECTED_TOPOLOGY_ATTESTATION_SHA256",
    "expected-topology-attestation-missing",
    blockers,
  );
  const expectedIssuerSecretAttestation = expectedDigest(
    "QUICK_LAUNCH_EXPECTED_ISSUER_SECRET_ATTESTATION_SHA256",
    "expected-issuer-secret-attestation-missing",
    blockers,
  );
  const expectedSponsorSecretAttestation = expectedDigest(
    "QUICK_LAUNCH_EXPECTED_SPONSOR_SECRET_ATTESTATION_SHA256",
    "expected-sponsor-secret-attestation-missing",
    blockers,
  );

  const [homeResponse, hostResponse, demoResponse] = await Promise.all([
    fetch(origin, { redirect: "error", headers: { "cache-control": "no-cache" } }),
    fetch(new URL("/api/quick-launch-readiness", origin), {
      redirect: "error",
      headers: { accept: "application/json", "cache-control": "no-cache" },
    }),
    fetch(new URL("/api/predicate/demo-credential", origin), {
      method: "HEAD",
      redirect: "error",
      headers: { "cache-control": "no-cache" },
    }),
  ]);

  const home = await homeResponse.text();
  const hostText = await hostResponse.text();
  let hostJson: unknown = null;
  try {
    hostJson = JSON.parse(hostText);
  } catch {
    blockers.push("host-readiness-response-not-json");
  }
  const host = sanitizeHostRecord(hostJson);
  const forbiddenMarkers = FORBIDDEN_RELEASE_MARKERS.filter((marker) => home.includes(marker));

  if (homeResponse.status !== 200) blockers.push("home-not-200");
  if (!home.includes("Quick Launch") || !home.includes("Base Sepolia")) blockers.push("quick-launch-markers-missing");
  if (forbiddenMarkers.length > 0) blockers.push("nonrelease-network-marker-present");
  if (demoResponse.status !== 404) blockers.push("demo-credential-route-present");
  if (hostResponse.status !== 200) blockers.push("host-readiness-not-200");
  if (!host) {
    blockers.push("host-readiness-record-missing");
  } else {
    if (host.schema !== QUICK_LAUNCH_HOST_READINESS_SCHEMA) blockers.push("host-readiness-schema-mismatch");
    if (host.release !== QUICK_LAUNCH_RELEASE.id || host.chainId !== QUICK_LAUNCH_RELEASE.chainId) {
      blockers.push("host-release-mismatch");
    }
    if (!host.transactionFree) blockers.push("host-record-not-transaction-free");
    if (!host.ready) blockers.push("host-reported-not-ready");
    if (expectedSourceRevision && host.sourceRevision !== expectedSourceRevision) blockers.push("source-revision-mismatch");
    if (expectedTopologyAttestation && host.topologyAttestationSha256 !== expectedTopologyAttestation) {
      blockers.push("topology-attestation-mismatch");
    }
    if (expectedIssuerSecretAttestation && host.issuerSecretAttestationSha256 !== expectedIssuerSecretAttestation) {
      blockers.push("issuer-secret-attestation-mismatch");
    }
    if (expectedSponsorSecretAttestation && host.sponsorSecretAttestationSha256 !== expectedSponsorSecretAttestation) {
      blockers.push("sponsor-secret-attestation-mismatch");
    }
  }

  const evidence = {
    schema: EVIDENCE_SCHEMA,
    observedAt: new Date().toISOString(),
    origin: origin.origin,
    transactionFree: true,
    publicSurface: {
      homeStatus: homeResponse.status,
      homeSha256: sha256(home),
      quickLaunchMarker: home.includes("Quick Launch"),
      baseSepoliaMarker: home.includes("Base Sepolia"),
      forbiddenMarkers,
      demoCredentialStatus: demoResponse.status,
      cloudFrontObserved: /cloudfront/iu.test(homeResponse.headers.get("via") ?? ""),
    },
    hostEndpoint: {
      status: hostResponse.status,
      responseSha256: sha256(hostText),
      record: host,
    },
    expectedBindings: {
      sourceRevision: expectedSourceRevision,
      topologyAttestationSha256: expectedTopologyAttestation,
      issuerSecretAttestationSha256: expectedIssuerSecretAttestation,
      sponsorSecretAttestationSha256: expectedSponsorSecretAttestation,
    },
    ready: blockers.length === 0,
    blockers: [...new Set(blockers)].sort(),
  };

  console.log(JSON.stringify(evidence, null, 2));
  if (!evidence.ready) process.exitCode = 1;
}

void main();
