/**
 * Fail-closed admission for one production V2 circuit profile.
 *
 * A manifest binds reviewed source/artifact/setup evidence to exact deployed
 * runtime code. Admission is intentionally read-only: it emits the governance
 * calldata required to register the circuit and, separately, enable the proof
 * path. It never signs or broadcasts a transaction.
 */
import {
  encodeFunctionData,
  getAddress,
  isAddress,
  isHex,
  keccak256,
  parseAbi,
  size,
  stringToHex,
  type Address,
  type Hex,
} from "viem";

export const ZK_PRODUCTION_PROFILE_SCHEMA =
  "org.proofofhumanity.zk-production-profile/1" as const;
export const ZK_PRODUCTION_PROFILE_VERSION = 1 as const;
export const ZK_PRODUCTION_PROFILE_ADMISSION_SCHEMA =
  "org.proofofhumanity.zk-production-profile-admission/1" as const;

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;
const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const PROHIBITED_RESEARCH_CIRCUIT_IDS = new Set<Hex>([
  keccak256(stringToHex("ubi2.zk-identity.v2.packed-status.research-1")),
  keccak256(stringToHex("ubi2.zk-identity.v2.dynamic-status-packed-research-1")),
]);
const PROHIBITED_RESEARCH_VERIFIER_CODEHASHES = new Set<Hex>([
  "0x51391a6337e1723e8ebc4a6a284e7f0a996d41b6ec476cdba56ddd1da7d964fa",
  "0x4bd30512624c62747d8a6e1b34405550f09939d798bb7f6c22dcb910b0352a7c",
]);
const UINT32_MAX = 0xffff_ffff;
const manifestKeys = [
  "schema",
  "version",
  "releaseStatus",
  "approvedAt",
  "sourceCommit",
  "circuit",
  "issuerKeyIds",
  "artifacts",
  "setup",
  "audits",
  "deviceBenchmarks",
  "targets",
  "manifestHash",
] as const;
const payloadKeys = manifestKeys.filter((key) => key !== "manifestHash");
const circuitKeys = [
  "name",
  "circuitId",
  "publicSignalLayoutVersion",
  "publicSignalCount",
  "proofSystem",
  "commitmentScheme",
  "issuerAuthenticationScheme",
  "statusTreeScheme",
  "compiler",
  "compilerVersion",
] as const;
const evidenceKeys = ["uri", "sha256"] as const;
const artifactKeys = [
  "parameterManifest",
  "circuitSource",
  "constraintSystem",
  "compilerLock",
  "proverArtifact",
  "verifierArtifact",
  "verifierSource",
  "publicSignalManifest",
] as const;
const setupKeys = ["kind", "contributionCount", "artifacts"] as const;
const setupArtifactKeys = ["kind", "uri", "sha256"] as const;
const auditKeys = ["criticalOpen", "highOpen", "reports"] as const;
const auditReportKeys = [
  "circuit",
  "cryptography",
  "solidity",
  "privacy",
  "qa",
  "reliability",
  "security",
  "acceptedRiskRegister",
] as const;
const deviceKeys = [
  "deviceClass",
  "platform",
  "browser",
  "sampleSize",
  "proofP95Ms",
  "peakMemoryBytes",
  "report",
] as const;
const targetKeys = [
  "network",
  "chainId",
  "deployedAtBlock",
  "governance",
  "governanceCodehash",
  "versionRegistry",
  "versionRegistryCodehash",
  "rawVerifier",
  "rawVerifierCodehash",
  "predicateProver",
  "predicateProverCodehash",
  "predicateVerifier",
  "predicateVerifierCodehash",
  "rawVerifierGas",
  "fullPathGas",
  "blockGasLimit",
  "gasReport",
  "integrationReport",
] as const;

export type ZkProductionProfileReleaseStatus = "candidate" | "production-approved";
export type ZkProductionSetupKind =
  | "circuit-specific-mpc"
  | "universal-updatable"
  | "transparent";
export type ZkProductionSetupEvidenceKind =
  | "phase1-transcript"
  | "phase2-transcript"
  | "final-beacon"
  | "universal-srs"
  | "contribution-verification"
  | "setup-rationale"
  | "independent-reproduction";

export interface ZkProductionEvidence {
  uri: string;
  sha256: Hex;
}

export interface ZkProductionSetupEvidence extends ZkProductionEvidence {
  kind: ZkProductionSetupEvidenceKind;
}

export interface ZkProductionProfileManifest {
  schema: typeof ZK_PRODUCTION_PROFILE_SCHEMA;
  version: typeof ZK_PRODUCTION_PROFILE_VERSION;
  releaseStatus: ZkProductionProfileReleaseStatus;
  approvedAt: string | null;
  sourceCommit: string;
  circuit: {
    name: string;
    circuitId: Hex;
    publicSignalLayoutVersion: 1;
    publicSignalCount: 18;
    proofSystem: string;
    commitmentScheme: string;
    issuerAuthenticationScheme: string;
    statusTreeScheme: string;
    compiler: string;
    compilerVersion: string;
  };
  issuerKeyIds: Hex[];
  artifacts: {
    parameterManifest: ZkProductionEvidence;
    circuitSource: ZkProductionEvidence;
    constraintSystem: ZkProductionEvidence;
    compilerLock: ZkProductionEvidence;
    proverArtifact: ZkProductionEvidence;
    verifierArtifact: ZkProductionEvidence;
    verifierSource: ZkProductionEvidence;
    publicSignalManifest: ZkProductionEvidence;
  };
  setup: {
    kind: ZkProductionSetupKind;
    contributionCount: number;
    artifacts: ZkProductionSetupEvidence[];
  };
  audits: {
    criticalOpen: number;
    highOpen: number;
    reports: {
      circuit: ZkProductionEvidence;
      cryptography: ZkProductionEvidence;
      solidity: ZkProductionEvidence;
      privacy: ZkProductionEvidence;
      qa: ZkProductionEvidence;
      reliability: ZkProductionEvidence;
      security: ZkProductionEvidence;
      acceptedRiskRegister: ZkProductionEvidence;
    };
  };
  deviceBenchmarks: Array<{
    deviceClass: string;
    platform: string;
    browser: string;
    sampleSize: number;
    proofP95Ms: number;
    peakMemoryBytes: number;
    report: ZkProductionEvidence;
  }>;
  targets: ZkProductionTarget[];
  manifestHash: Hex;
}

export interface ZkProductionTarget {
  network: string;
  chainId: number;
  deployedAtBlock: string;
  governance: Address;
  governanceCodehash: Hex;
  versionRegistry: Address;
  versionRegistryCodehash: Hex;
  rawVerifier: Address;
  rawVerifierCodehash: Hex;
  predicateProver: Address;
  predicateProverCodehash: Hex;
  predicateVerifier: Address;
  predicateVerifierCodehash: Hex;
  rawVerifierGas: number;
  fullPathGas: number;
  blockGasLimit: number;
  gasReport: ZkProductionEvidence;
  integrationReport: ZkProductionEvidence;
}

export type ZkProductionProfileInput = Omit<
  ZkProductionProfileManifest,
  "schema" | "version" | "manifestHash"
>;

export interface ZkProductionDeploymentSnapshot {
  chainId: number;
  observedAtBlock: string;
  registryOwner: Address;
  predicateVerifierOwner: Address;
  predicateVerifierProver: Address;
  circuitRegistration: {
    verifier: Address;
    verifierCodehash: Hex;
    active: boolean;
  };
  runtimeBytecode: {
    governance: Hex;
    versionRegistry: Hex;
    rawVerifier: Hex;
    predicateProver: Hex;
    predicateVerifier: Hex;
  };
}

export interface ZkProductionProfileAdmission {
  schema: typeof ZK_PRODUCTION_PROFILE_ADMISSION_SCHEMA;
  manifestHash: Hex;
  network: string;
  chainId: number;
  observedAtBlock: string;
  governance: Address;
  circuitId: Hex;
  verifierCodehash: Hex;
  registrationCalls: Array<{ to: Address; data: Hex; operation: string }>;
  proofPathActivation: {
    to: Address;
    data: Hex;
    operation: "set-predicate-prover";
    executeOnlyAfterStatusAdmission: true;
  };
}

const registryAbi = parseAbi([
  "function registerCircuit(bytes32 circuitId,address verifier)",
  "function authorizeIssuer(bytes32 circuitId,bytes32 issuerKeyId)",
]);
const predicateVerifierAbi = parseAbi(["function setPredicateProver(address newProver)"]);

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function decimal(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
  return value;
}

function positiveDecimal(value: unknown, label: string): string {
  const normalized = decimal(value, label);
  if (BigInt(normalized) === 0n) throw new Error(`${label} must be greater than zero`);
  return normalized;
}

function identifier(value: unknown, label: string, maximum = 128): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    !/^[a-z0-9][a-z0-9._:/+-]*$/u.test(value)
  ) {
    throw new Error(`${label} must be a lowercase public identifier of at most ${maximum} characters`);
  }
  return value;
}

function bytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (!allowZero && normalized === ZERO_BYTES32) throw new Error(`${label} must not be zero`);
  return normalized;
}

function address(value: unknown, label: string, allowZero = false): Address {
  if (typeof value !== "string" || !isAddress(value, { strict: true })) {
    throw new Error(`${label} must be a checksummed address`);
  }
  const normalized = getAddress(value);
  if (!allowZero && normalized === ZERO_ADDRESS) throw new Error(`${label} must not be zero`);
  return normalized;
}

function evidence(value: unknown, label: string): ZkProductionEvidence {
  const candidate = object(value, label);
  exactKeys(candidate, evidenceKeys, label);
  if (typeof candidate.uri !== "string" || candidate.uri.length > 512) {
    throw new Error(`${label} URI must be a bounded string`);
  }
  if (candidate.uri.startsWith("https://")) {
    const parsed = new URL(candidate.uri);
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new Error(`${label} URI must not contain credentials, a query or a fragment`);
    }
  } else if (!/^ipfs:\/\/[a-zA-Z0-9]+(?:\/[a-zA-Z0-9._/-]+)?$/u.test(candidate.uri)) {
    throw new Error(`${label} URI must use https or ipfs`);
  }
  return { uri: candidate.uri, sha256: bytes32(candidate.sha256, `${label} SHA-256`) };
}

function setup(value: unknown): ZkProductionProfileManifest["setup"] {
  const candidate = object(value, "production setup");
  exactKeys(candidate, setupKeys, "production setup");
  if (
    candidate.kind !== "circuit-specific-mpc" &&
    candidate.kind !== "universal-updatable" &&
    candidate.kind !== "transparent"
  ) {
    throw new Error("unsupported production setup kind");
  }
  if (!Array.isArray(candidate.artifacts)) throw new Error("production setup artifacts must be an array");
  const artifacts = candidate.artifacts.map((value, index) => {
    const artifact = object(value, `production setup artifact ${index}`);
    exactKeys(artifact, setupArtifactKeys, `production setup artifact ${index}`);
    const kind = artifact.kind;
    if (
      kind !== "phase1-transcript" &&
      kind !== "phase2-transcript" &&
      kind !== "final-beacon" &&
      kind !== "universal-srs" &&
      kind !== "contribution-verification" &&
      kind !== "setup-rationale" &&
      kind !== "independent-reproduction"
    ) {
      throw new Error("unsupported production setup evidence kind");
    }
    return {
      kind: kind as ZkProductionSetupEvidenceKind,
      ...evidence({ uri: artifact.uri, sha256: artifact.sha256 }, `setup ${kind}`),
    };
  }).sort((left, right) => left.kind.localeCompare(right.kind));
  const actual = artifacts.map(({ kind }) => kind).sort();
  const expected: ZkProductionSetupEvidenceKind[] =
    candidate.kind === "circuit-specific-mpc"
      ? [
          "contribution-verification",
          "final-beacon",
          "independent-reproduction",
          "phase1-transcript",
          "phase2-transcript",
        ]
      : candidate.kind === "universal-updatable"
        ? ["contribution-verification", "independent-reproduction", "universal-srs"]
        : ["independent-reproduction", "setup-rationale"];
  expected.sort();
  if (actual.length !== expected.length || actual.some((kind, index) => kind !== expected[index])) {
    throw new Error(`production setup evidence does not match ${candidate.kind}`);
  }
  const contributionCount = integer(candidate.contributionCount, "setup contribution count", 0, 10_000);
  if (
    (candidate.kind === "circuit-specific-mpc" && contributionCount < 3) ||
    (candidate.kind === "universal-updatable" && contributionCount < 1) ||
    (candidate.kind === "transparent" && contributionCount !== 0)
  ) {
    throw new Error("setup contribution count does not match the selected setup kind");
  }
  return { kind: candidate.kind, contributionCount, artifacts };
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`);
  return `{${entries.join(",")}}`;
}

function payloadHash(payload: Omit<ZkProductionProfileManifest, "manifestHash">): Hex {
  return keccak256(stringToHex(canonicalJson(payload)));
}

function normalizePayload(value: unknown): Omit<ZkProductionProfileManifest, "manifestHash"> {
  const candidate = object(value, "production profile");
  exactKeys(candidate, payloadKeys, "production profile");
  if (candidate.schema !== ZK_PRODUCTION_PROFILE_SCHEMA || candidate.version !== 1) {
    throw new Error("unsupported production profile schema or version");
  }
  if (candidate.releaseStatus !== "candidate" && candidate.releaseStatus !== "production-approved") {
    throw new Error("unsupported production profile release status");
  }
  let approvedAt: string | null = null;
  if (candidate.releaseStatus === "production-approved") {
    if (typeof candidate.approvedAt !== "string" || !Number.isFinite(Date.parse(candidate.approvedAt))) {
      throw new Error("approved production profile requires an ISO approval timestamp");
    }
    approvedAt = new Date(candidate.approvedAt).toISOString();
    if (approvedAt !== candidate.approvedAt) throw new Error("approval timestamp must be canonical ISO-8601 UTC");
  } else if (candidate.approvedAt !== null) {
    throw new Error("candidate production profile must not claim an approval timestamp");
  }
  if (typeof candidate.sourceCommit !== "string" || !/^[0-9a-f]{40}$/u.test(candidate.sourceCommit)) {
    throw new Error("production profile source commit must be a full lowercase Git commit");
  }

  const rawCircuit = object(candidate.circuit, "production circuit");
  exactKeys(rawCircuit, circuitKeys, "production circuit");
  if (rawCircuit.publicSignalLayoutVersion !== 1 || rawCircuit.publicSignalCount !== 18) {
    throw new Error("production circuit must implement the frozen V1 18-signal layout");
  }
  const circuit = {
    name: identifier(rawCircuit.name, "circuit name"),
    circuitId: bytes32(rawCircuit.circuitId, "circuit id"),
    publicSignalLayoutVersion: 1 as const,
    publicSignalCount: 18 as const,
    proofSystem: identifier(rawCircuit.proofSystem, "proof system"),
    commitmentScheme: identifier(rawCircuit.commitmentScheme, "commitment scheme"),
    issuerAuthenticationScheme: identifier(
      rawCircuit.issuerAuthenticationScheme,
      "issuer authentication scheme",
    ),
    statusTreeScheme: identifier(rawCircuit.statusTreeScheme, "status tree scheme"),
    compiler: identifier(rawCircuit.compiler, "circuit compiler"),
    compilerVersion: identifier(rawCircuit.compilerVersion, "circuit compiler version"),
  };

  if (!Array.isArray(candidate.issuerKeyIds) || candidate.issuerKeyIds.length === 0) {
    throw new Error("production profile requires at least one issuer key id");
  }
  const issuerKeyIds = candidate.issuerKeyIds
    .map((value, index) => bytes32(value, `issuer key id ${index}`))
    .sort();
  if (new Set(issuerKeyIds).size !== issuerKeyIds.length) {
    throw new Error("production profile issuer key ids must be unique");
  }

  const rawArtifacts = object(candidate.artifacts, "production artifacts");
  exactKeys(rawArtifacts, artifactKeys, "production artifacts");
  const artifacts = Object.fromEntries(
    artifactKeys.map((key) => [key, evidence(rawArtifacts[key], `production artifact ${key}`)]),
  ) as unknown as ZkProductionProfileManifest["artifacts"];

  const rawAudits = object(candidate.audits, "production audits");
  exactKeys(rawAudits, auditKeys, "production audits");
  const rawReports = object(rawAudits.reports, "production audit reports");
  exactKeys(rawReports, auditReportKeys, "production audit reports");
  const reports = Object.fromEntries(
    auditReportKeys.map((key) => [key, evidence(rawReports[key], `production report ${key}`)]),
  ) as unknown as ZkProductionProfileManifest["audits"]["reports"];
  const audits = {
    criticalOpen: integer(rawAudits.criticalOpen, "open Critical findings", 0, UINT32_MAX),
    highOpen: integer(rawAudits.highOpen, "open High findings", 0, UINT32_MAX),
    reports,
  };

  if (!Array.isArray(candidate.deviceBenchmarks) || candidate.deviceBenchmarks.length === 0) {
    throw new Error("production profile requires device benchmark evidence");
  }
  const deviceBenchmarks = candidate.deviceBenchmarks
    .map((value, index) => {
      const benchmark = object(value, `device benchmark ${index}`);
      exactKeys(benchmark, deviceKeys, `device benchmark ${index}`);
      return {
        deviceClass: identifier(benchmark.deviceClass, `device benchmark ${index} class`),
        platform: identifier(benchmark.platform, `device benchmark ${index} platform`),
        browser: identifier(benchmark.browser, `device benchmark ${index} browser`),
        sampleSize: integer(benchmark.sampleSize, `device benchmark ${index} sample size`, 1, 1_000_000),
        proofP95Ms: integer(benchmark.proofP95Ms, `device benchmark ${index} proof p95`, 1, 3_600_000),
        peakMemoryBytes: integer(
          benchmark.peakMemoryBytes,
          `device benchmark ${index} peak memory`,
          1,
          64 * 1024 ** 3,
        ),
        report: evidence(benchmark.report, `device benchmark ${index} report`),
      };
    })
    .sort((left, right) =>
      `${left.deviceClass}\u0000${left.platform}\u0000${left.browser}`.localeCompare(
        `${right.deviceClass}\u0000${right.platform}\u0000${right.browser}`,
      ),
    );
  const benchmarkEnvironments = deviceBenchmarks.map(
    ({ deviceClass, platform, browser }) => `${deviceClass}\u0000${platform}\u0000${browser}`,
  );
  if (new Set(benchmarkEnvironments).size !== benchmarkEnvironments.length) {
    throw new Error("production profile device benchmark environments must be unique");
  }

  if (!Array.isArray(candidate.targets) || candidate.targets.length === 0) {
    throw new Error("production profile requires at least one target chain");
  }
  const targets = candidate.targets
    .map((value, index) => {
      const target = object(value, `production target ${index}`);
      exactKeys(target, targetKeys, `production target ${index}`);
      const rawVerifierGas = integer(target.rawVerifierGas, `target ${index} raw verifier gas`, 1, UINT32_MAX);
      const fullPathGas = integer(target.fullPathGas, `target ${index} full path gas`, 1, UINT32_MAX);
      const blockGasLimit = integer(target.blockGasLimit, `target ${index} block gas limit`, 1, UINT32_MAX);
      if (rawVerifierGas > fullPathGas || fullPathGas >= blockGasLimit) {
        throw new Error(`target ${index} gas measurements do not fit the target block budget`);
      }
      const addresses = [
        address(target.governance, `target ${index} governance`),
        address(target.versionRegistry, `target ${index} version registry`),
        address(target.rawVerifier, `target ${index} raw verifier`),
        address(target.predicateProver, `target ${index} predicate prover`),
        address(target.predicateVerifier, `target ${index} predicate verifier`),
      ];
      if (new Set(addresses).size !== addresses.length) {
        throw new Error(`target ${index} deployment addresses must be distinct`);
      }
      return {
        network: identifier(target.network, `target ${index} network`),
        chainId: integer(target.chainId, `target ${index} chain id`, 1, Number.MAX_SAFE_INTEGER),
        deployedAtBlock: positiveDecimal(
          target.deployedAtBlock,
          `target ${index} deployment block`,
        ),
        governance: addresses[0]!,
        governanceCodehash: bytes32(target.governanceCodehash, `target ${index} governance codehash`),
        versionRegistry: addresses[1]!,
        versionRegistryCodehash: bytes32(
          target.versionRegistryCodehash,
          `target ${index} version registry codehash`,
        ),
        rawVerifier: addresses[2]!,
        rawVerifierCodehash: bytes32(target.rawVerifierCodehash, `target ${index} raw verifier codehash`),
        predicateProver: addresses[3]!,
        predicateProverCodehash: bytes32(
          target.predicateProverCodehash,
          `target ${index} predicate prover codehash`,
        ),
        predicateVerifier: addresses[4]!,
        predicateVerifierCodehash: bytes32(
          target.predicateVerifierCodehash,
          `target ${index} predicate verifier codehash`,
        ),
        rawVerifierGas,
        fullPathGas,
        blockGasLimit,
        gasReport: evidence(target.gasReport, `target ${index} gas report`),
        integrationReport: evidence(target.integrationReport, `target ${index} integration report`),
      };
    })
    .sort((left, right) => left.chainId - right.chainId);
  if (new Set(targets.map(({ chainId }) => chainId)).size !== targets.length) {
    throw new Error("production profile target chain ids must be unique");
  }

  return {
    schema: ZK_PRODUCTION_PROFILE_SCHEMA,
    version: ZK_PRODUCTION_PROFILE_VERSION,
    releaseStatus: candidate.releaseStatus,
    approvedAt,
    sourceCommit: candidate.sourceCommit,
    circuit,
    issuerKeyIds,
    artifacts,
    setup: setup(candidate.setup),
    audits,
    deviceBenchmarks,
    targets,
  };
}

/** Create a canonically ordered candidate or approved manifest and bind it with Keccak. */
export function createZkProductionProfileManifest(
  input: ZkProductionProfileInput,
): ZkProductionProfileManifest {
  const payload = normalizePayload({
    ...input,
    schema: ZK_PRODUCTION_PROFILE_SCHEMA,
    version: ZK_PRODUCTION_PROFILE_VERSION,
  });
  return { ...payload, manifestHash: payloadHash(payload) };
}

/** Strictly parse a serialized manifest and reject any field or digest drift. */
export function parseZkProductionProfileManifest(value: unknown): ZkProductionProfileManifest {
  const candidate = object(value, "production profile manifest");
  exactKeys(candidate, manifestKeys, "production profile manifest");
  const { manifestHash, ...rawPayload } = candidate;
  const payload = normalizePayload(rawPayload);
  const expected = payloadHash(payload);
  if (bytes32(manifestHash, "production profile manifest hash") !== expected) {
    throw new Error("production profile manifest hash mismatch");
  }
  return { ...payload, manifestHash: expected };
}

/** Stable canonical JSON suitable for code review and content-addressed publication. */
export function serializeZkProductionProfileManifest(value: unknown): string {
  return `${JSON.stringify(parseZkProductionProfileManifest(value), null, 2)}\n`;
}

function runtimeCodehash(bytecode: unknown, label: string): Hex {
  if (typeof bytecode !== "string" || !isHex(bytecode) || bytecode === "0x") {
    throw new Error(`${label} runtime bytecode is missing`);
  }
  return keccak256(bytecode);
}

function assertProductionEvidence(manifest: ZkProductionProfileManifest): void {
  if (manifest.releaseStatus !== "production-approved" || manifest.approvedAt === null) {
    throw new Error("production profile has not been approved");
  }
  if (manifest.audits.criticalOpen !== 0 || manifest.audits.highOpen !== 0) {
    throw new Error("production profile has open Critical or High findings");
  }
  const mobile = manifest.deviceBenchmarks.filter(({ deviceClass }) => deviceClass === "mid-range-mobile");
  if (mobile.length === 0 || mobile.some(({ sampleSize }) => sampleSize < 20)) {
    throw new Error("production profile requires a representative mid-range-mobile benchmark");
  }
  const publicText = canonicalJson(manifest).toLowerCase();
  if (/(research|fixture|\.invalid|localhost|testnet)/u.test(publicText)) {
    throw new Error("production-approved profile references non-production evidence or identifiers");
  }
  if (PROHIBITED_RESEARCH_CIRCUIT_IDS.has(manifest.circuit.circuitId)) {
    throw new Error("production-approved profile uses a prohibited research circuit id");
  }
  if (
    manifest.targets.some(({ rawVerifierCodehash }) =>
      PROHIBITED_RESEARCH_VERIFIER_CODEHASHES.has(rawVerifierCodehash),
    )
  ) {
    throw new Error("production-approved profile uses a prohibited research verifier codehash");
  }
}

function assertRuntime(actual: Hex, expected: Hex, label: string): void {
  const codehash = runtimeCodehash(actual, label);
  if (codehash !== expected) throw new Error(`${label} runtime codehash mismatch`);
}

/**
 * Admit one exact live deployment and emit governance calldata.
 *
 * The circuit must still be unregistered and the permanent host's proof path
 * must still be unset. Status-root/policy admission is a later, separately
 * evidenced gate; callers must not execute `proofPathActivation` before it.
 */
export function admitZkProductionProfile(input: {
  manifest: unknown;
  snapshot: ZkProductionDeploymentSnapshot;
}): ZkProductionProfileAdmission {
  const manifest = parseZkProductionProfileManifest(input.manifest);
  assertProductionEvidence(manifest);
  const chainId = integer(input.snapshot.chainId, "deployment chain id", 1, Number.MAX_SAFE_INTEGER);
  const target = manifest.targets.find((candidate) => candidate.chainId === chainId);
  if (target === undefined) throw new Error("deployment chain is absent from the production profile");
  const observedAtBlock = positiveDecimal(
    input.snapshot.observedAtBlock,
    "deployment observation block",
  );
  if (BigInt(observedAtBlock) < BigInt(target.deployedAtBlock)) {
    throw new Error("deployment observation predates the approved deployment");
  }

  if (address(input.snapshot.registryOwner, "version registry owner") !== target.governance) {
    throw new Error("version registry is not owned by the approved governance contract");
  }
  if (address(input.snapshot.predicateVerifierOwner, "predicate verifier owner") !== target.governance) {
    throw new Error("predicate verifier is not owned by the approved governance contract");
  }
  if (address(input.snapshot.predicateVerifierProver, "active predicate prover", true) !== ZERO_ADDRESS) {
    throw new Error("predicate verifier proof path must remain unset before admission");
  }

  const registration = input.snapshot.circuitRegistration;
  if (
    address(registration.verifier, "registered circuit verifier", true) !== ZERO_ADDRESS ||
    bytes32(registration.verifierCodehash, "registered circuit codehash", true) !== ZERO_BYTES32 ||
    registration.active
  ) {
    throw new Error("production circuit id is already registered");
  }

  assertRuntime(input.snapshot.runtimeBytecode.governance, target.governanceCodehash, "governance");
  assertRuntime(
    input.snapshot.runtimeBytecode.versionRegistry,
    target.versionRegistryCodehash,
    "version registry",
  );
  assertRuntime(input.snapshot.runtimeBytecode.rawVerifier, target.rawVerifierCodehash, "raw verifier");
  assertRuntime(
    input.snapshot.runtimeBytecode.predicateProver,
    target.predicateProverCodehash,
    "predicate prover",
  );
  assertRuntime(
    input.snapshot.runtimeBytecode.predicateVerifier,
    target.predicateVerifierCodehash,
    "predicate verifier",
  );

  const registrationCalls: ZkProductionProfileAdmission["registrationCalls"] = [
    {
      to: target.versionRegistry,
      data: encodeFunctionData({
        abi: registryAbi,
        functionName: "registerCircuit",
        args: [manifest.circuit.circuitId, target.rawVerifier],
      }),
      operation: "register-circuit",
    },
    ...manifest.issuerKeyIds.map((issuerKeyId) => ({
      to: target.versionRegistry,
      data: encodeFunctionData({
        abi: registryAbi,
        functionName: "authorizeIssuer",
        args: [manifest.circuit.circuitId, issuerKeyId],
      }),
      operation: "authorize-issuer",
    })),
  ];

  return {
    schema: ZK_PRODUCTION_PROFILE_ADMISSION_SCHEMA,
    manifestHash: manifest.manifestHash,
    network: target.network,
    chainId,
    observedAtBlock,
    governance: target.governance,
    circuitId: manifest.circuit.circuitId,
    verifierCodehash: target.rawVerifierCodehash,
    registrationCalls,
    proofPathActivation: {
      to: target.predicateVerifier,
      data: encodeFunctionData({
        abi: predicateVerifierAbi,
        functionName: "setPredicateProver",
        args: [target.predicateProver],
      }),
      operation: "set-predicate-prover",
      executeOnlyAfterStatusAdmission: true,
    },
  };
}
