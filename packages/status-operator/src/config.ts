import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { getAddress, isAddress, isHex, size, type Address, type Hex } from "viem";
import { canonicalOperatorId } from "./artifact";

export const ZK_IDENTITY_STATUS_OPERATOR_CONFIG_SCHEMA =
  "org.proofofhumanity.v2-packed-status-operator-config/1" as const;
export const ZK_IDENTITY_STATUS_FLEET_CONFIG_SCHEMA =
  "org.proofofhumanity.v2-packed-status-fleet-config/1" as const;

export interface ZkIdentityStatusOperatorConfig {
  schema: typeof ZK_IDENTITY_STATUS_OPERATOR_CONFIG_SCHEMA;
  operatorId: string;
  rpcUrl: string;
  chainId: number;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  signerAddress: Address;
  initialCheckpointPath: string;
  stateDirectory: string;
  builderPath: string;
  builderSha256: Hex;
  castPath: string;
  castSha256: Hex;
  keystorePath: string;
  passwordFile: string;
  pollIntervalSeconds: number;
  listenHost: "127.0.0.1" | "::1";
  listenPort: number;
}

export interface ZkIdentityStatusFleetOperatorConfig {
  operatorId: string;
  signerAddress: Address;
  baseUrl: string;
}

export interface ZkIdentityStatusFleetConfig {
  schema: typeof ZK_IDENTITY_STATUS_FLEET_CONFIG_SCHEMA;
  referenceRpcUrl: string;
  chainId: number;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  threshold: number;
  maxHeartbeatAgeSeconds: number;
  maxBlockLag: number;
  requestTimeoutMs: number;
  operators: ZkIdentityStatusFleetOperatorConfig[];
}

const operatorConfigKeys = [
  "schema",
  "operatorId",
  "rpcUrl",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "signerAddress",
  "initialCheckpointPath",
  "stateDirectory",
  "builderPath",
  "builderSha256",
  "castPath",
  "castSha256",
  "keystorePath",
  "passwordFile",
  "pollIntervalSeconds",
  "listenHost",
  "listenPort",
] as const;
const fleetConfigKeys = [
  "schema",
  "referenceRpcUrl",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "threshold",
  "maxHeartbeatAgeSeconds",
  "maxBlockLag",
  "requestTimeoutMs",
  "operators",
] as const;
const fleetOperatorKeys = ["operatorId", "signerAddress", "baseUrl"] as const;

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

function positiveInteger(value: unknown, label: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > maximum
  ) {
    throw new Error(`${label} must be a bounded positive integer`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, label: string, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new Error(`${label} must be a bounded non-negative integer`);
  }
  return value;
}

function address(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a non-zero EVM address`);
  }
  return getAddress(value);
}

function bytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32 || BigInt(value) === 0n) {
    throw new Error(`${label} must be non-zero bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function absolutePath(value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path`);
  }
  return value;
}

function secureUrl(
  value: unknown,
  label: string,
  options: { allowPath: boolean; allowSearch: boolean },
): string {
  if (typeof value !== "string") throw new Error(`${label} must be a URL`);
  const parsed = new URL(value);
  const loopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
  if (
    (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    (!options.allowPath && parsed.pathname !== "/") ||
    (!options.allowSearch && parsed.search !== "")
  ) {
    throw new Error(`${label} must use HTTPS, or HTTP only on loopback, without URL credentials`);
  }
  const normalized = parsed.toString();
  return options.allowPath ? normalized.replace(/\/+$/u, "") : normalized;
}

export function parseZkIdentityStatusOperatorConfig(
  value: unknown,
): ZkIdentityStatusOperatorConfig {
  const candidate = object(value, "status operator config");
  exactKeys(candidate, operatorConfigKeys, "status operator config");
  if (candidate.schema !== ZK_IDENTITY_STATUS_OPERATOR_CONFIG_SCHEMA) {
    throw new Error("unsupported status operator config schema");
  }
  if (candidate.listenHost !== "127.0.0.1" && candidate.listenHost !== "::1") {
    throw new Error("status operator HTTP server must bind to loopback");
  }
  const pollIntervalSeconds = positiveInteger(
    candidate.pollIntervalSeconds,
    "status operator poll interval",
    3_600,
  );
  if (pollIntervalSeconds < 5) {
    throw new Error("status operator poll interval must be at least five seconds");
  }
  return {
    schema: ZK_IDENTITY_STATUS_OPERATOR_CONFIG_SCHEMA,
    operatorId: canonicalOperatorId(candidate.operatorId),
    rpcUrl: secureUrl(candidate.rpcUrl, "status operator RPC URL", {
      allowPath: true,
      allowSearch: true,
    }),
    chainId: positiveInteger(candidate.chainId, "status operator chain id"),
    issuanceRegistry: address(candidate.issuanceRegistry, "status operator registry"),
    issuerKeyId: bytes32(candidate.issuerKeyId, "status operator issuer key id"),
    signerAddress: address(candidate.signerAddress, "status operator signer"),
    initialCheckpointPath: absolutePath(
      candidate.initialCheckpointPath,
      "status operator initial checkpoint",
    ),
    stateDirectory: absolutePath(candidate.stateDirectory, "status operator state directory"),
    builderPath: absolutePath(candidate.builderPath, "status operator builder"),
    builderSha256: bytes32(candidate.builderSha256, "status operator builder SHA-256"),
    castPath: absolutePath(candidate.castPath, "status operator cast binary"),
    castSha256: bytes32(candidate.castSha256, "status operator cast SHA-256"),
    keystorePath: absolutePath(candidate.keystorePath, "status operator keystore"),
    passwordFile: absolutePath(candidate.passwordFile, "status operator password file"),
    pollIntervalSeconds,
    listenHost: candidate.listenHost,
    listenPort: positiveInteger(candidate.listenPort, "status operator listen port", 65_535),
  };
}

export function parseZkIdentityStatusFleetConfig(value: unknown): ZkIdentityStatusFleetConfig {
  const candidate = object(value, "status fleet config");
  exactKeys(candidate, fleetConfigKeys, "status fleet config");
  if (candidate.schema !== ZK_IDENTITY_STATUS_FLEET_CONFIG_SCHEMA) {
    throw new Error("unsupported status fleet config schema");
  }
  if (!Array.isArray(candidate.operators) || candidate.operators.length < 2) {
    throw new Error("status fleet requires at least two operators");
  }
  const operators = candidate.operators.map((value) => {
    const operator = object(value, "status fleet operator");
    exactKeys(operator, fleetOperatorKeys, "status fleet operator");
    return {
      operatorId: canonicalOperatorId(operator.operatorId),
      signerAddress: address(operator.signerAddress, "status fleet signer"),
      baseUrl: secureUrl(operator.baseUrl, "status fleet operator URL", {
        allowPath: true,
        allowSearch: false,
      }),
    };
  });
  if (
    new Set(operators.map(({ operatorId }) => operatorId)).size !== operators.length ||
    new Set(operators.map(({ signerAddress }) => signerAddress)).size !== operators.length ||
    new Set(operators.map(({ baseUrl }) => baseUrl)).size !== operators.length
  ) {
    throw new Error("status fleet operator ids, signers, and URLs must be distinct");
  }
  const threshold = positiveInteger(candidate.threshold, "status fleet threshold", operators.length);
  if (threshold < 2) throw new Error("status fleet threshold must be at least two");
  return {
    schema: ZK_IDENTITY_STATUS_FLEET_CONFIG_SCHEMA,
    referenceRpcUrl: secureUrl(candidate.referenceRpcUrl, "status fleet reference RPC URL", {
      allowPath: true,
      allowSearch: true,
    }),
    chainId: positiveInteger(candidate.chainId, "status fleet chain id"),
    issuanceRegistry: address(candidate.issuanceRegistry, "status fleet registry"),
    issuerKeyId: bytes32(candidate.issuerKeyId, "status fleet issuer key id"),
    threshold,
    maxHeartbeatAgeSeconds: positiveInteger(
      candidate.maxHeartbeatAgeSeconds,
      "status fleet heartbeat age",
      86_400,
    ),
    maxBlockLag: nonNegativeInteger(candidate.maxBlockLag, "status fleet block lag", 512),
    requestTimeoutMs: positiveInteger(candidate.requestTimeoutMs, "status fleet timeout", 60_000),
    operators,
  };
}

export async function readStrictJsonFile(path: string): Promise<unknown> {
  if (!isAbsolute(path)) throw new Error("configuration path must be absolute");
  return JSON.parse(await readFile(path, "utf8"));
}
