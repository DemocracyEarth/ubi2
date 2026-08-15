/**
 * Authenticated publication manifests for governed v2 dynamic-status roots.
 *
 * A manifest is public metadata. It contains no holder or passport data. The
 * EIP-712 domain binds its signature to one destination chain and one
 * ZkIdentityVersionRegistry, preventing cross-chain or cross-registry replay.
 */
import {
  getAddress,
  hashTypedData,
  isAddress,
  isHex,
  recoverTypedDataAddress,
  size,
  type Address,
  type Hex,
} from "viem";
import {
  dynamicStatusPolicyRegistration,
  normalizeZkIdentityPolicy,
  type DynamicStatusPolicy,
  type DynamicStatusPolicyInput,
} from "./zk-identity-policy";

export const ZK_DYNAMIC_STATUS_MANIFEST_SCHEMA =
  "org.proofofhumanity.zk-dynamic-status-manifest" as const;
export const ZK_DYNAMIC_STATUS_MANIFEST_VERSION = 1 as const;
export const ZK_DYNAMIC_STATUS_MANIFEST_DOMAIN_NAME =
  "ProofOfHumanityZkDynamicStatus" as const;
export const ZK_DYNAMIC_STATUS_MANIFEST_DOMAIN_VERSION = "1" as const;
export const ZK_DYNAMIC_STATUS_MANIFEST_PRIMARY_TYPE = "DynamicStatusManifest" as const;

export const zkDynamicStatusManifestTypes = {
  DynamicStatusManifest: [
    { name: "policyHash", type: "bytes32" },
    { name: "providerIdHash", type: "bytes32" },
    { name: "listVersionHash", type: "bytes32" },
    { name: "statusRoot", type: "bytes32" },
    { name: "publishedAt", type: "uint32" },
    { name: "maximumAgeSeconds", type: "uint32" },
  ],
} as const;

export interface DynamicStatusManifest {
  schema: typeof ZK_DYNAMIC_STATUS_MANIFEST_SCHEMA;
  version: typeof ZK_DYNAMIC_STATUS_MANIFEST_VERSION;
  chainId: number;
  registry: Address;
  status: "sanctions-clear";
  providerId: string;
  listVersion: string;
  policyHash: Hex;
  providerIdHash: Hex;
  listVersionHash: Hex;
  statusRoot: Hex;
  /** Unix timestamp in seconds for the exact committed snapshot. */
  publishedAt: number;
  maximumAgeSeconds: number;
  /** Derived display value; it is not an independent signed field. */
  expiresAt: number;
}

export interface SignedDynamicStatusManifest {
  manifest: DynamicStatusManifest;
  signature: Hex;
}

export interface CreateDynamicStatusManifestInput {
  chainId: number;
  registry: Address;
  policy: DynamicStatusPolicy | DynamicStatusPolicyInput;
  publishedAt: number;
}

const manifestKeys = [
  "schema",
  "version",
  "chainId",
  "registry",
  "status",
  "providerId",
  "listVersion",
  "policyHash",
  "providerIdHash",
  "listVersionHash",
  "statusRoot",
  "publishedAt",
  "maximumAgeSeconds",
  "expiresAt",
] as const;

function positiveChainId(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error("dynamic-status manifest chain id must be a positive integer");
  }
  return value;
}

function nonZeroAddress(value: unknown): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error("dynamic-status manifest registry must be a non-zero EVM address");
  }
  return getAddress(value);
}

function exactBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function exactManifestKeys(value: Record<string, unknown>): void {
  const actual = Object.keys(value).sort();
  const expected = [...manifestKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("dynamic-status manifest contains missing or unknown fields");
  }
}

/** Build a canonical manifest from human-readable policy metadata. */
export function createDynamicStatusManifest(
  input: CreateDynamicStatusManifestInput,
): DynamicStatusManifest {
  const chainId = positiveChainId(input.chainId);
  const registry = nonZeroAddress(input.registry);
  const policy = normalizeZkIdentityPolicy(input.policy);
  if (policy.kind !== "dynamic-status") throw new Error("dynamic status policy required");
  const registration = dynamicStatusPolicyRegistration({
    policy,
    publishedAt: input.publishedAt,
  });
  return {
    schema: ZK_DYNAMIC_STATUS_MANIFEST_SCHEMA,
    version: ZK_DYNAMIC_STATUS_MANIFEST_VERSION,
    chainId,
    registry,
    status: policy.status,
    providerId: policy.providerId,
    listVersion: policy.listVersion,
    ...registration,
    expiresAt: registration.publishedAt + registration.maximumAgeSeconds,
  };
}

/**
 * Validate an untrusted parsed manifest and recompute every redundant hash.
 * Rejection is whole-manifest: labels cannot drift away from signed hashes.
 */
export function parseDynamicStatusManifest(value: unknown): DynamicStatusManifest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("dynamic-status manifest must be an object");
  }
  const candidate = value as Record<string, unknown>;
  exactManifestKeys(candidate);
  if (candidate.schema !== ZK_DYNAMIC_STATUS_MANIFEST_SCHEMA) {
    throw new Error("unsupported dynamic-status manifest schema");
  }
  if (candidate.version !== ZK_DYNAMIC_STATUS_MANIFEST_VERSION) {
    throw new Error("unsupported dynamic-status manifest version");
  }
  if (
    candidate.status !== "sanctions-clear" ||
    typeof candidate.providerId !== "string" ||
    typeof candidate.listVersion !== "string" ||
    typeof candidate.publishedAt !== "number" ||
    typeof candidate.maximumAgeSeconds !== "number"
  ) {
    throw new Error("invalid dynamic-status manifest policy metadata");
  }

  const normalized = createDynamicStatusManifest({
    chainId: positiveChainId(candidate.chainId),
    registry: nonZeroAddress(candidate.registry),
    policy: {
      kind: "dynamic-status",
      status: candidate.status,
      providerId: candidate.providerId,
      listVersion: candidate.listVersion,
      statusRoot: exactBytes32(candidate.statusRoot, "dynamic-status manifest root"),
      maximumAgeSeconds: candidate.maximumAgeSeconds,
    },
    publishedAt: candidate.publishedAt,
  });

  for (const key of ["policyHash", "providerIdHash", "listVersionHash"] as const) {
    if (exactBytes32(candidate[key], `dynamic-status manifest ${key}`) !== normalized[key]) {
      throw new Error(`dynamic-status manifest ${key} does not match canonical metadata`);
    }
  }
  if (candidate.expiresAt !== normalized.expiresAt) {
    throw new Error("dynamic-status manifest expiry does not match publication time and maximum age");
  }
  return normalized;
}

function typedData(manifest: DynamicStatusManifest) {
  return {
    domain: {
      name: ZK_DYNAMIC_STATUS_MANIFEST_DOMAIN_NAME,
      version: ZK_DYNAMIC_STATUS_MANIFEST_DOMAIN_VERSION,
      chainId: manifest.chainId,
      verifyingContract: manifest.registry,
    },
    types: zkDynamicStatusManifestTypes,
    primaryType: ZK_DYNAMIC_STATUS_MANIFEST_PRIMARY_TYPE,
    message: {
      policyHash: manifest.policyHash,
      providerIdHash: manifest.providerIdHash,
      listVersionHash: manifest.listVersionHash,
      statusRoot: manifest.statusRoot,
      publishedAt: manifest.publishedAt,
      maximumAgeSeconds: manifest.maximumAgeSeconds,
    },
  } as const;
}

/** EIP-712 payload for a wallet, HSM or offline publication key. */
export function dynamicStatusManifestTypedData(value: unknown) {
  return typedData(parseDynamicStatusManifest(value));
}

/** Deterministic, chain- and registry-bound manifest digest. */
export function dynamicStatusManifestDigest(value: unknown): Hex {
  return hashTypedData(dynamicStatusManifestTypedData(value));
}

/** Recover the EOA publication key that authenticated a manifest. */
export function recoverDynamicStatusManifestSigner(
  value: unknown,
  signature: Hex,
): Promise<Address> {
  if (!isHex(signature)) throw new Error("dynamic-status manifest signature must be hex");
  return recoverTypedDataAddress({
    ...dynamicStatusManifestTypedData(value),
    signature,
  });
}

/**
 * Verify an EOA publication signature against an application-configured key.
 * The expected publisher must come from trusted configuration, never from the
 * downloaded manifest itself. ERC-1271 publishers require an RPC contract call.
 */
export async function verifyDynamicStatusManifestSignature(
  value: unknown,
  signature: Hex,
  expectedPublisher: Address,
): Promise<boolean> {
  const expected = nonZeroAddress(expectedPublisher);
  try {
    const recovered = await recoverDynamicStatusManifestSigner(value, signature);
    return recovered === expected;
  } catch {
    return false;
  }
}

/** Reject a snapshot that is not yet published or is past its inclusive window. */
export function assertDynamicStatusManifestCurrent(
  value: unknown,
  nowUnixSeconds: number,
): DynamicStatusManifest {
  if (!Number.isSafeInteger(nowUnixSeconds) || nowUnixSeconds < 0) {
    throw new Error("current Unix time must be a non-negative integer");
  }
  const manifest = parseDynamicStatusManifest(value);
  if (nowUnixSeconds < manifest.publishedAt) {
    throw new Error("dynamic-status manifest is from the future");
  }
  if (nowUnixSeconds > manifest.expiresAt) {
    throw new Error("dynamic-status manifest is stale");
  }
  return manifest;
}

/** Canonical JSON key order for transport and fixtures. */
export function serializeDynamicStatusManifest(value: unknown): string {
  return JSON.stringify(parseDynamicStatusManifest(value), null, 2);
}
