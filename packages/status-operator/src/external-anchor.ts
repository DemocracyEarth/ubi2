import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, mkdir, open, readFile, unlink } from "node:fs/promises";
import { isIP } from "node:net";
import { basename, dirname, isAbsolute, join } from "node:path";
import { getAddress, isAddress, isHex, size, type Address, type Hex } from "viem";
import { canonicalOperatorId } from "./artifact";
import { parseZkIdentityStatusOperatorConfig } from "./config";
import {
  verifyZkIdentityStatusTestnetHostAttestationEvidence,
  verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig,
  type ZkIdentityStatusTestnetHostAttestationEvidence,
} from "./host-attestation";
import {
  parseZkIdentityStatusTestnetTrustRecord,
  verifyZkIdentityStatusTestnetPreflightEvidence,
  type ZkIdentityStatusTestnetPreflightEvidence,
} from "./readiness";

export const ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REFERENCES_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-external-anchor-references/1" as const;
export const ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_MANIFEST_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-external-anchor-manifest/1" as const;
export const ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REPORT_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-external-anchor-report/1" as const;
export const ZK_IDENTITY_STATUS_TESTNET_PROVIDER_INDEPENDENCE_SUBJECT_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-provider-independence-subject/1" as const;

export type ZkIdentityStatusTestnetExternalAnchorReceiptKind =
  | "authoritative-timestamp"
  | "provider-independence";

export interface ZkIdentityStatusTestnetExternalAnchorReceiptReference {
  kind: ZkIdentityStatusTestnetExternalAnchorReceiptKind;
  authorityId: string;
  subjectSha256: Hex;
  receiptIssuedAt: string;
  receiptUrl: string;
  receiptSha256: Hex;
}

export interface ZkIdentityStatusTestnetExternalAnchorReferences {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REFERENCES_SCHEMA;
  authoritativeTimestamps: readonly [
    ZkIdentityStatusTestnetExternalAnchorReceiptReference,
    ZkIdentityStatusTestnetExternalAnchorReceiptReference,
  ];
  providerIndependence: ZkIdentityStatusTestnetExternalAnchorReceiptReference;
}

export interface ZkIdentityStatusTestnetProviderIndependenceSubject {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_PROVIDER_INDEPENDENCE_SUBJECT_SCHEMA;
  preflightEvidenceSha256: Hex;
  operators: readonly [
    {
      operatorId: string;
      hostId: string;
      volumeId: string;
      rpcProviderId: string;
    },
    {
      operatorId: string;
      hostId: string;
      volumeId: string;
      rpcProviderId: string;
    },
  ];
  fleetHostId: string;
  referenceRpcProviderId: string;
}

export interface ZkIdentityStatusTestnetExternalAnchorIdentity {
  preflightEvidenceSha256: Hex;
  network: string;
  chainId: number;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  providerIndependenceSubjectSha256: Hex;
}

export interface ZkIdentityStatusTestnetExternalAnchorHost {
  operatorId: string;
  hostId: string;
  volumeId: string;
  signerAddress: Address;
  observedAt: string;
  evidenceSha256: Hex;
  authoritativeTimestamp: ZkIdentityStatusTestnetExternalAnchorReceiptReference;
}

export interface ZkIdentityStatusTestnetExternalAnchorReport {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REPORT_SCHEMA;
  intrinsicEvidenceValid: true;
  liveReadinessClaimed: false;
  externalChecksRequired: readonly [
    "AUTHORITATIVE_TIMESTAMP_RECEIPT_AUTHENTICITY",
    "PROVIDER_INDEPENDENCE_RECEIPT_AUTHENTICITY",
  ];
}

export interface ZkIdentityStatusTestnetExternalAnchorManifest {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_MANIFEST_SCHEMA;
  identity: ZkIdentityStatusTestnetExternalAnchorIdentity;
  hosts: readonly [
    ZkIdentityStatusTestnetExternalAnchorHost,
    ZkIdentityStatusTestnetExternalAnchorHost,
  ];
  providerIndependence: ZkIdentityStatusTestnetExternalAnchorReceiptReference;
  report: ZkIdentityStatusTestnetExternalAnchorReport;
  manifestSha256: Hex;
}

const referencesKeys = ["schema", "authoritativeTimestamps", "providerIndependence"] as const;
const receiptKeys = [
  "kind",
  "authorityId",
  "subjectSha256",
  "receiptIssuedAt",
  "receiptUrl",
  "receiptSha256",
] as const;
const manifestKeys = [
  "schema",
  "identity",
  "hosts",
  "providerIndependence",
  "report",
  "manifestSha256",
] as const;
const identityKeys = [
  "preflightEvidenceSha256",
  "network",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "providerIndependenceSubjectSha256",
] as const;
const hostKeys = [
  "operatorId",
  "hostId",
  "volumeId",
  "signerAddress",
  "observedAt",
  "evidenceSha256",
  "authoritativeTimestamp",
] as const;
const reportKeys = [
  "schema",
  "intrinsicEvidenceValid",
  "liveReadinessClaimed",
  "externalChecksRequired",
] as const;
const externalChecksRequired = [
  "AUTHORITATIVE_TIMESTAMP_RECEIPT_AUTHENTICITY",
  "PROVIDER_INDEPENDENCE_RECEIPT_AUTHENTICITY",
] as const;

function object(value: unknown, description: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  description: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${description} contains missing or unknown fields`);
  }
}

function label(value: unknown, description: string): string {
  if (typeof value !== "string" || !/^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/u.test(value)) {
    throw new Error(`${description} must be a canonical public label`);
  }
  return value;
}

function integer(value: unknown, description: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${description} must be a positive integer`);
  }
  return value;
}

function address(value: unknown, description: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${description} must be a non-zero EVM address`);
  }
  return getAddress(value);
}

function bytes32(value: unknown, description: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32 || BigInt(value) === 0n) {
    throw new Error(`${description} must be non-zero bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function timestamp(value: unknown, description: string): string {
  if (typeof value !== "string") throw new Error(`${description} must be a timestamp`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error(`${description} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

function publicReceiptUrl(value: unknown, description: string): string {
  if (typeof value !== "string" || value.length > 2_048) {
    throw new Error(`${description} must be a bounded public HTTPS URL`);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${description} must be a bounded public HTTPS URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.port !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname === "/" ||
    !parsed.hostname.includes(".") ||
    isIP(parsed.hostname.replace(/^\[|\]$/gu, "")) !== 0 ||
    parsed.hostname === "localhost" ||
    parsed.hostname.endsWith(".localhost") ||
    parsed.hostname.endsWith(".local") ||
    parsed.toString() !== value
  ) {
    throw new Error(
      `${description} must be canonical public HTTPS without credentials, port, query, fragment, or a local host`,
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`);
  return `{${entries.join(",")}}`;
}

function sha256(value: unknown): Hex {
  return `0x${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function parseReceiptReference(
  value: unknown,
  expectedKind: ZkIdentityStatusTestnetExternalAnchorReceiptKind,
  description: string,
): ZkIdentityStatusTestnetExternalAnchorReceiptReference {
  const candidate = object(value, description);
  exactKeys(candidate, receiptKeys, description);
  if (candidate.kind !== expectedKind) {
    throw new Error(`${description} has the wrong receipt kind`);
  }
  return {
    kind: expectedKind,
    authorityId: label(candidate.authorityId, `${description} authority id`),
    subjectSha256: bytes32(candidate.subjectSha256, `${description} subject SHA-256`),
    receiptIssuedAt: timestamp(candidate.receiptIssuedAt, `${description} issued at`),
    receiptUrl: publicReceiptUrl(candidate.receiptUrl, `${description} URL`),
    receiptSha256: bytes32(candidate.receiptSha256, `${description} SHA-256`),
  };
}

function requireDistinctReceiptReferences(
  references: readonly ZkIdentityStatusTestnetExternalAnchorReceiptReference[],
): void {
  if (new Set(references.map(({ receiptUrl }) => receiptUrl)).size !== references.length) {
    throw new Error("external anchor receipt URLs must be distinct");
  }
  if (new Set(references.map(({ receiptSha256 }) => receiptSha256)).size !== references.length) {
    throw new Error("external anchor receipt SHA-256 values must be distinct");
  }
}

export function parseZkIdentityStatusTestnetExternalAnchorReferences(
  value: unknown,
): ZkIdentityStatusTestnetExternalAnchorReferences {
  const candidate = object(value, "canonical testnet external anchor references");
  exactKeys(candidate, referencesKeys, "canonical testnet external anchor references");
  if (candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REFERENCES_SCHEMA) {
    throw new Error("unsupported canonical testnet external anchor references schema");
  }
  if (!Array.isArray(candidate.authoritativeTimestamps) || candidate.authoritativeTimestamps.length !== 2) {
    throw new Error("canonical testnet external anchor references require exactly two timestamps");
  }
  const authoritativeTimestamps = candidate.authoritativeTimestamps.map((reference, index) =>
    parseReceiptReference(
      reference,
      "authoritative-timestamp",
      `canonical testnet authoritative timestamp ${index + 1}`,
    ),
  ) as unknown as ZkIdentityStatusTestnetExternalAnchorReferences["authoritativeTimestamps"];
  if (
    authoritativeTimestamps[0].subjectSha256 === authoritativeTimestamps[1].subjectSha256
  ) {
    throw new Error("canonical testnet authoritative timestamps must bind distinct subjects");
  }
  const providerIndependence = parseReceiptReference(
    candidate.providerIndependence,
    "provider-independence",
    "canonical testnet provider independence receipt",
  );
  requireDistinctReceiptReferences([...authoritativeTimestamps, providerIndependence]);
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REFERENCES_SCHEMA,
    authoritativeTimestamps,
    providerIndependence,
  };
}

export function createZkIdentityStatusTestnetProviderIndependenceSubject(
  preflightEvidenceValue: unknown,
): ZkIdentityStatusTestnetProviderIndependenceSubject {
  const preflightEvidence = verifyZkIdentityStatusTestnetPreflightEvidence(preflightEvidenceValue);
  if (!preflightEvidence.report.ready) {
    throw new Error("canonical testnet preflight evidence is not ready");
  }
  const trustRecord = parseZkIdentityStatusTestnetTrustRecord(preflightEvidence.trustRecord);
  const operators = trustRecord.operators.map(({ operatorId, hostId, volumeId, rpcProviderId }) => ({
    operatorId,
    hostId,
    volumeId,
    rpcProviderId,
  })) as unknown as ZkIdentityStatusTestnetProviderIndependenceSubject["operators"];
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_PROVIDER_INDEPENDENCE_SUBJECT_SCHEMA,
    preflightEvidenceSha256: preflightEvidence.evidenceSha256,
    operators,
    fleetHostId: trustRecord.fleetHostId,
    referenceRpcProviderId: trustRecord.referenceRpcProviderId,
  };
}

export function zkIdentityStatusTestnetProviderIndependenceSubjectSha256(
  preflightEvidenceValue: unknown,
): Hex {
  return sha256(
    createZkIdentityStatusTestnetProviderIndependenceSubject(preflightEvidenceValue),
  );
}

function report(): ZkIdentityStatusTestnetExternalAnchorReport {
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REPORT_SCHEMA,
    intrinsicEvidenceValid: true,
    liveReadinessClaimed: false,
    externalChecksRequired,
  };
}

function manifestPayload(
  value: Omit<ZkIdentityStatusTestnetExternalAnchorManifest, "manifestSha256">,
): Omit<ZkIdentityStatusTestnetExternalAnchorManifest, "manifestSha256"> {
  return {
    schema: value.schema,
    identity: value.identity,
    hosts: value.hosts,
    providerIndependence: value.providerIndependence,
    report: value.report,
  };
}

function matchTimestamp(
  evidence: ZkIdentityStatusTestnetHostAttestationEvidence,
  references: ZkIdentityStatusTestnetExternalAnchorReferences,
): ZkIdentityStatusTestnetExternalAnchorReceiptReference {
  const matching = references.authoritativeTimestamps.filter(
    ({ subjectSha256 }) => subjectSha256 === evidence.evidenceSha256,
  );
  if (matching.length !== 1) {
    throw new Error("each host attestation requires exactly one authoritative timestamp receipt");
  }
  const receipt = matching[0]!;
  if (new Date(receipt.receiptIssuedAt).getTime() < new Date(evidence.report.observedAt).getTime()) {
    throw new Error("authoritative timestamp receipt cannot predate its host attestation");
  }
  return receipt;
}

export function createZkIdentityStatusTestnetExternalAnchorManifest(input: {
  preflightEvidence: unknown;
  hostAttestations: readonly unknown[];
  operatorConfigs: readonly unknown[];
  references: unknown;
}): ZkIdentityStatusTestnetExternalAnchorManifest {
  const preflightEvidence = verifyZkIdentityStatusTestnetPreflightEvidence(input.preflightEvidence);
  if (!preflightEvidence.report.ready) {
    throw new Error("canonical testnet preflight evidence is not ready");
  }
  if (input.hostAttestations.length !== 2 || input.operatorConfigs.length !== 2) {
    throw new Error("external anchor manifest requires exactly two host attestations and configs");
  }
  const trustRecord = parseZkIdentityStatusTestnetTrustRecord(preflightEvidence.trustRecord);
  const operatorConfigs = input.operatorConfigs.map(parseZkIdentityStatusOperatorConfig);
  if (new Set(operatorConfigs.map(({ operatorId }) => operatorId)).size !== 2) {
    throw new Error("external anchor manifest operator configs must be distinct");
  }
  const references = parseZkIdentityStatusTestnetExternalAnchorReferences(input.references);
  const attestations = input.hostAttestations
    .map((value) => verifyZkIdentityStatusTestnetHostAttestationEvidence(value))
    .sort((left, right) => left.identity.operatorId.localeCompare(right.identity.operatorId));
  if (
    new Set(attestations.map(({ evidenceSha256 }) => evidenceSha256)).size !== 2 ||
    new Set(attestations.map(({ identity }) => identity.operatorId)).size !== 2 ||
    new Set(attestations.map(({ identity }) => identity.hostId)).size !== 2 ||
    new Set(attestations.map(({ identity }) => identity.volumeId)).size !== 2
  ) {
    throw new Error("external anchor manifest host attestations must be independent and distinct");
  }
  const expectedOperatorIds = trustRecord.operators.map(({ operatorId }) => operatorId).sort();
  if (
    attestations.some(({ report: hostReport }) => !hostReport.ready) ||
    attestations.some(({ identity: hostIdentity }, index) =>
      hostIdentity.operatorId !== expectedOperatorIds[index] ||
      hostIdentity.preflightEvidenceSha256 !== preflightEvidence.evidenceSha256,
    )
  ) {
    throw new Error("external anchor manifest requires two ready hosts bound to the same preflight");
  }
  const verifiedAttestations = attestations.map((evidence) => {
    const operatorConfig = operatorConfigs.find(
      ({ operatorId }) => operatorId === evidence.identity.operatorId,
    );
    if (operatorConfig === undefined) {
      throw new Error("external anchor manifest does not have a config for every host attestation");
    }
    return verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig({
      evidence,
      preflightEvidence,
      operatorConfig,
    });
  });
  const providerIndependenceSubjectSha256 = sha256(
    createZkIdentityStatusTestnetProviderIndependenceSubject(preflightEvidence),
  );
  if (references.providerIndependence.subjectSha256 !== providerIndependenceSubjectSha256) {
    throw new Error("provider independence receipt does not bind the reviewed preflight topology");
  }
  const hosts = verifiedAttestations.map((evidence) => ({
    operatorId: evidence.identity.operatorId,
    hostId: evidence.identity.hostId,
    volumeId: evidence.identity.volumeId,
    signerAddress: evidence.identity.signerAddress,
    observedAt: evidence.report.observedAt,
    evidenceSha256: evidence.evidenceSha256,
    authoritativeTimestamp: matchTimestamp(evidence, references),
  })) as unknown as ZkIdentityStatusTestnetExternalAnchorManifest["hosts"];
  const payload = {
    schema: ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_MANIFEST_SCHEMA,
    identity: {
      preflightEvidenceSha256: preflightEvidence.evidenceSha256,
      network: trustRecord.network,
      chainId: trustRecord.chainId,
      issuanceRegistry: trustRecord.issuanceRegistry,
      issuerKeyId: trustRecord.issuerKeyId,
      providerIndependenceSubjectSha256,
    },
    hosts,
    providerIndependence: references.providerIndependence,
    report: report(),
  } satisfies Omit<ZkIdentityStatusTestnetExternalAnchorManifest, "manifestSha256">;
  return { ...payload, manifestSha256: sha256(manifestPayload(payload)) };
}

function parseIdentity(value: unknown): ZkIdentityStatusTestnetExternalAnchorIdentity {
  const candidate = object(value, "canonical testnet external anchor identity");
  exactKeys(candidate, identityKeys, "canonical testnet external anchor identity");
  return {
    preflightEvidenceSha256: bytes32(
      candidate.preflightEvidenceSha256,
      "external anchor preflight evidence SHA-256",
    ),
    network: label(candidate.network, "external anchor network"),
    chainId: integer(candidate.chainId, "external anchor chain id"),
    issuanceRegistry: address(candidate.issuanceRegistry, "external anchor issuance registry"),
    issuerKeyId: bytes32(candidate.issuerKeyId, "external anchor issuer key id"),
    providerIndependenceSubjectSha256: bytes32(
      candidate.providerIndependenceSubjectSha256,
      "external anchor provider independence subject SHA-256",
    ),
  };
}

function parseHost(value: unknown): ZkIdentityStatusTestnetExternalAnchorHost {
  const candidate = object(value, "canonical testnet external anchor host");
  exactKeys(candidate, hostKeys, "canonical testnet external anchor host");
  const evidenceSha256 = bytes32(candidate.evidenceSha256, "external anchor host evidence SHA-256");
  const authoritativeTimestamp = parseReceiptReference(
    candidate.authoritativeTimestamp,
    "authoritative-timestamp",
    "canonical testnet host authoritative timestamp",
  );
  if (authoritativeTimestamp.subjectSha256 !== evidenceSha256) {
    throw new Error("host authoritative timestamp does not bind the host evidence");
  }
  const observedAt = timestamp(candidate.observedAt, "external anchor host observed at");
  if (
    new Date(authoritativeTimestamp.receiptIssuedAt).getTime() < new Date(observedAt).getTime()
  ) {
    throw new Error("host authoritative timestamp receipt predates the host observation");
  }
  return {
    operatorId: canonicalOperatorId(candidate.operatorId),
    hostId: label(candidate.hostId, "external anchor host id"),
    volumeId: label(candidate.volumeId, "external anchor volume id"),
    signerAddress: address(candidate.signerAddress, "external anchor host signer"),
    observedAt,
    evidenceSha256,
    authoritativeTimestamp,
  };
}

function parseReport(value: unknown): ZkIdentityStatusTestnetExternalAnchorReport {
  const candidate = object(value, "canonical testnet external anchor report");
  exactKeys(candidate, reportKeys, "canonical testnet external anchor report");
  if (
    candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REPORT_SCHEMA ||
    candidate.intrinsicEvidenceValid !== true ||
    candidate.liveReadinessClaimed !== false ||
    canonicalJson(candidate.externalChecksRequired) !== canonicalJson(externalChecksRequired)
  ) {
    throw new Error("canonical testnet external anchor report is invalid");
  }
  return report();
}

export function verifyZkIdentityStatusTestnetExternalAnchorManifest(
  value: unknown,
): ZkIdentityStatusTestnetExternalAnchorManifest {
  const candidate = object(value, "canonical testnet external anchor manifest");
  exactKeys(candidate, manifestKeys, "canonical testnet external anchor manifest");
  if (candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_MANIFEST_SCHEMA) {
    throw new Error("unsupported canonical testnet external anchor manifest schema");
  }
  const suppliedSha256 = bytes32(candidate.manifestSha256, "external anchor manifest SHA-256");
  const rawPayload = {
    schema: candidate.schema,
    identity: candidate.identity,
    hosts: candidate.hosts,
    providerIndependence: candidate.providerIndependence,
    report: candidate.report,
  };
  if (sha256(rawPayload) !== suppliedSha256) {
    throw new Error("canonical testnet external anchor manifest SHA-256 mismatch");
  }
  if (!Array.isArray(candidate.hosts) || candidate.hosts.length !== 2) {
    throw new Error("canonical testnet external anchor manifest requires exactly two hosts");
  }
  const identity = parseIdentity(candidate.identity);
  const hosts = candidate.hosts.map(parseHost) as unknown as ZkIdentityStatusTestnetExternalAnchorManifest["hosts"];
  const providerIndependence = parseReceiptReference(
    candidate.providerIndependence,
    "provider-independence",
    "canonical testnet provider independence receipt",
  );
  const parsedReport = parseReport(candidate.report);
  if (
    hosts[0].operatorId.localeCompare(hosts[1].operatorId) >= 0 ||
    new Set(hosts.map(({ hostId }) => hostId)).size !== 2 ||
    new Set(hosts.map(({ volumeId }) => volumeId)).size !== 2 ||
    new Set(hosts.map(({ signerAddress }) => signerAddress)).size !== 2 ||
    new Set(hosts.map(({ evidenceSha256 }) => evidenceSha256)).size !== 2
  ) {
    throw new Error("canonical testnet external anchor hosts must be sorted and distinct");
  }
  if (providerIndependence.subjectSha256 !== identity.providerIndependenceSubjectSha256) {
    throw new Error("provider independence receipt does not bind the manifest identity");
  }
  requireDistinctReceiptReferences([
    hosts[0].authoritativeTimestamp,
    hosts[1].authoritativeTimestamp,
    providerIndependence,
  ]);
  const normalizedPayload = {
    schema: ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_MANIFEST_SCHEMA,
    identity,
    hosts,
    providerIndependence,
    report: parsedReport,
  };
  if (canonicalJson(normalizedPayload) !== canonicalJson(rawPayload)) {
    throw new Error("canonical testnet external anchor manifest is not canonically encoded");
  }
  return { ...normalizedPayload, manifestSha256: suppliedSha256 };
}

export function verifyZkIdentityStatusTestnetExternalAnchorManifestAgainstEvidence(input: {
  manifest: unknown;
  preflightEvidence: unknown;
  hostAttestations: readonly unknown[];
  operatorConfigs: readonly unknown[];
}): ZkIdentityStatusTestnetExternalAnchorManifest {
  const manifest = verifyZkIdentityStatusTestnetExternalAnchorManifest(input.manifest);
  const expected = createZkIdentityStatusTestnetExternalAnchorManifest({
    preflightEvidence: input.preflightEvidence,
    hostAttestations: input.hostAttestations,
    operatorConfigs: input.operatorConfigs,
    references: {
      schema: ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REFERENCES_SCHEMA,
      authoritativeTimestamps: manifest.hosts.map(({ authoritativeTimestamp }) =>
        authoritativeTimestamp,
      ),
      providerIndependence: manifest.providerIndependence,
    },
  });
  if (canonicalJson(expected) !== canonicalJson(manifest)) {
    throw new Error("external anchor manifest does not match the supplied evidence and configs");
  }
  return manifest;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } catch (error) {
    const code =
      error !== null && typeof error === "object" && "code" in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code !== "EINVAL" && code !== "ENOTSUP") throw error;
  } finally {
    await handle.close();
  }
}

export async function writeZkIdentityStatusTestnetExternalAnchorManifest(
  path: string,
  manifest: unknown,
): Promise<void> {
  if (!isAbsolute(path)) {
    throw new Error("canonical testnet external anchor manifest path must be absolute");
  }
  const verified = verifyZkIdentityStatusTestnetExternalAnchorManifest(manifest);
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = join(directory, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    await handle.writeFile(`${JSON.stringify(verified)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    try {
      await link(temporary, path);
    } catch (error) {
      const code =
        error !== null && typeof error === "object" && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (code !== "EEXIST") throw error;
      throw Object.assign(new Error("canonical testnet external anchor manifest already exists"), {
        code: "EVIDENCE_ALREADY_EXISTS",
      });
    }
    await unlink(temporary);
    await syncDirectory(directory);
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function readZkIdentityStatusTestnetExternalAnchorManifest(
  path: string,
): Promise<ZkIdentityStatusTestnetExternalAnchorManifest> {
  if (!isAbsolute(path)) {
    throw new Error("canonical testnet external anchor manifest path must be absolute");
  }
  return verifyZkIdentityStatusTestnetExternalAnchorManifest(
    JSON.parse(await readFile(path, "utf8")),
  );
}
