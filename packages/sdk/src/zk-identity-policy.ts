/**
 * Canonical v2 ZK identity policies and EVM presentation bindings.
 *
 * These hashes are the semantic contract between policy builders, circuits and
 * verifier adapters. They do not generate or verify a ZK proof. Proof-system
 * public-signal layouts remain versioned separately so a circuit can change
 * without changing what a policy means.
 */
import {
  encodeAbiParameters,
  getAddress,
  isAddress,
  isHex,
  keccak256,
  size,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";

export const ZK_IDENTITY_POLICY_SCHEMA = "org.proofofhumanity.zk-policy" as const;
export const ZK_IDENTITY_POLICY_VERSION = 1 as const;
export const ZK_PRESENTATION_SCHEMA = "org.proofofhumanity.zk-presentation" as const;
export const ZK_PRESENTATION_VERSION = 1 as const;

export type CountryAttribute = "nationality" | "issuing-state";
export type CountryOperator = "in" | "not-in";
export type DocumentAssurance = "passive-auth" | "chip-auth";
export type NullifierMode = "single-use" | "stable-pseudonym";

interface PolicyBase {
  schema: typeof ZK_IDENTITY_POLICY_SCHEMA;
  version: typeof ZK_IDENTITY_POLICY_VERSION;
}

export interface AgeRangePolicy extends PolicyBase {
  kind: "age-range";
  minimumInclusive: number;
  maximumExclusive: number | null;
  /** ISO civil date chosen by the consumer; the verifier must enforce freshness. */
  referenceDate: string;
}

export interface CountrySetPolicy extends PolicyBase {
  kind: "country-set";
  attribute: CountryAttribute;
  operator: CountryOperator;
  /** Human-readable, versioned registry identifier. */
  setId: string;
  /** Commitment/root published by the country-set registry. */
  setRoot: Hex;
}

export interface DocumentValidityPolicy extends PolicyBase {
  kind: "document-validity";
  referenceDate: string;
  minimumRemainingDays: number;
}

export interface DocumentAuthenticityPolicy extends PolicyBase {
  kind: "document-authenticity";
  minimumAssurance: DocumentAssurance;
}

export interface UniqueHumanPolicy extends PolicyBase {
  kind: "unique-human";
  scope: string;
  nullifierMode: NullifierMode;
}

export interface DynamicStatusPolicy extends PolicyBase {
  kind: "dynamic-status";
  status: "sanctions-clear";
  providerId: string;
  listVersion: string;
  statusRoot: Hex;
  maximumAgeSeconds: number;
}

export type DynamicStatusPolicyInput = Omit<DynamicStatusPolicy, keyof PolicyBase>;

/** Exact governance arguments for one versioned dynamic-status snapshot. */
export interface DynamicStatusPolicyRegistration {
  policyHash: Hex;
  providerIdHash: Hex;
  listVersionHash: Hex;
  statusRoot: Hex;
  /** Unix timestamp in seconds at which the committed snapshot was published. */
  publishedAt: number;
  maximumAgeSeconds: number;
}

export interface PrivateFieldMatchPolicy extends PolicyBase {
  kind: "private-field-match";
  field: "name";
  /** Commitment to the comparison value; the name itself is never public. */
  expectedCommitment: Hex;
  consentRequired: true;
}

export type ZkIdentityPolicy =
  | AgeRangePolicy
  | CountrySetPolicy
  | DocumentValidityPolicy
  | DocumentAuthenticityPolicy
  | UniqueHumanPolicy
  | DynamicStatusPolicy
  | PrivateFieldMatchPolicy;

export type ZkIdentityPolicyInput =
  | Omit<AgeRangePolicy, keyof PolicyBase>
  | Omit<CountrySetPolicy, keyof PolicyBase>
  | Omit<DocumentValidityPolicy, keyof PolicyBase>
  | Omit<DocumentAuthenticityPolicy, keyof PolicyBase>
  | Omit<UniqueHumanPolicy, keyof PolicyBase>
  | DynamicStatusPolicyInput
  | Omit<PrivateFieldMatchPolicy, keyof PolicyBase>;

export interface ZkPresentationBinding {
  schema: typeof ZK_PRESENTATION_SCHEMA;
  version: typeof ZK_PRESENTATION_VERSION;
  policyHash: Hex;
  chainId: number;
  verifier: Address;
  consumer: Address;
  subject: Address;
  context: Hex;
  challenge: Hex;
  epoch: number;
}

export type ZkPresentationBindingInput = Omit<ZkPresentationBinding, "schema" | "version">;

const policyDomainHash = keccak256(stringToBytes(ZK_IDENTITY_POLICY_SCHEMA));
const presentationDomainHash = keccak256(stringToBytes(ZK_PRESENTATION_SCHEMA));

function assertInteger(value: number, label: string, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
}

function assertIdentifier(value: string, label: string, maxLength = 96): string {
  const normalized = value.trim();
  if (!/^[a-z0-9][a-z0-9._:/-]*$/u.test(normalized) || normalized.length > maxLength) {
    throw new Error(`${label} must be a lowercase public identifier of at most ${maxLength} characters`);
  }
  return normalized;
}

function bytes32(value: Hex, label: string): Hex {
  if (!isHex(value) || size(value) !== 32) throw new Error(`${label} must be bytes32`);
  return value.toLowerCase() as Hex;
}

function nonZeroBytes32(value: Hex, label: string): Hex {
  const normalized = bytes32(value, label);
  if (BigInt(normalized) === 0n) throw new Error(`${label} must not be zero`);
  return normalized;
}

function civilDate(value: string, label: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(value);
  if (!match) throw new Error(`${label} must use YYYY-MM-DD`);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    year < 1970 ||
    year > 2500 ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new Error(`${label} must be a valid civil date from 1970 through 2500`);
  }
  return value;
}

function packedDate(value: string): number {
  return Number(value.replaceAll("-", ""));
}

/** Validate and normalize a policy before hashing, storage or display. */
export function normalizeZkIdentityPolicy<T extends ZkIdentityPolicyInput>(input: T): Extract<ZkIdentityPolicy, { kind: T["kind"] }>;
export function normalizeZkIdentityPolicy(input: ZkIdentityPolicy): ZkIdentityPolicy;
export function normalizeZkIdentityPolicy(input: ZkIdentityPolicy | ZkIdentityPolicyInput): ZkIdentityPolicy {
  if (!input || typeof input !== "object") throw new Error("ZK identity policy must be an object");
  const tagged = input as Partial<PolicyBase> & ZkIdentityPolicyInput;
  if (tagged.schema !== undefined && tagged.schema !== ZK_IDENTITY_POLICY_SCHEMA) {
    throw new Error("unsupported ZK identity policy schema");
  }
  if (tagged.version !== undefined && tagged.version !== ZK_IDENTITY_POLICY_VERSION) {
    throw new Error("unsupported ZK identity policy version");
  }
  const base = { schema: ZK_IDENTITY_POLICY_SCHEMA, version: ZK_IDENTITY_POLICY_VERSION } as const;
  switch (input.kind) {
    case "age-range": {
      assertInteger(input.minimumInclusive, "minimum age", 0, 125);
      if (input.maximumExclusive !== null) {
        assertInteger(input.maximumExclusive, "maximum age", 1, 126);
        if (input.maximumExclusive <= input.minimumInclusive) {
          throw new Error("maximum age must be greater than minimum age");
        }
      }
      return { ...base, kind: input.kind, minimumInclusive: input.minimumInclusive, maximumExclusive: input.maximumExclusive, referenceDate: civilDate(input.referenceDate, "age reference date") };
    }
    case "country-set":
      if (input.attribute !== "nationality" && input.attribute !== "issuing-state") {
        throw new Error("unsupported private country attribute");
      }
      if (input.operator !== "in" && input.operator !== "not-in") {
        throw new Error("unsupported country-set operator");
      }
      return {
        ...base,
        kind: input.kind,
        attribute: input.attribute,
        operator: input.operator,
        setId: assertIdentifier(input.setId, "country set id"),
        setRoot: bytes32(input.setRoot, "country set root"),
      };
    case "document-validity":
      assertInteger(input.minimumRemainingDays, "minimum remaining days", 0, 3650);
      return { ...base, kind: input.kind, referenceDate: civilDate(input.referenceDate, "validity reference date"), minimumRemainingDays: input.minimumRemainingDays };
    case "document-authenticity":
      if (input.minimumAssurance !== "passive-auth" && input.minimumAssurance !== "chip-auth") {
        throw new Error("unsupported document assurance");
      }
      return { ...base, kind: input.kind, minimumAssurance: input.minimumAssurance };
    case "unique-human":
      if (input.nullifierMode !== "single-use" && input.nullifierMode !== "stable-pseudonym") {
        throw new Error("unsupported nullifier mode");
      }
      return { ...base, kind: input.kind, scope: assertIdentifier(input.scope, "uniqueness scope", 128), nullifierMode: input.nullifierMode };
    case "dynamic-status":
      if (input.status !== "sanctions-clear") throw new Error("unsupported dynamic status");
      assertInteger(input.maximumAgeSeconds, "maximum status age", 60, 31_536_000);
      return {
        ...base,
        kind: input.kind,
        status: input.status,
        providerId: assertIdentifier(input.providerId, "status provider id"),
        listVersion: assertIdentifier(input.listVersion, "status list version"),
        statusRoot: nonZeroBytes32(input.statusRoot, "status root"),
        maximumAgeSeconds: input.maximumAgeSeconds,
      };
    case "private-field-match":
      if (input.field !== "name" || input.consentRequired !== true) {
        throw new Error("private name matching requires explicit consent");
      }
      return { ...base, kind: input.kind, field: input.field, expectedCommitment: bytes32(input.expectedCommitment, "expected field commitment"), consentRequired: true };
    default:
      throw new Error("unsupported ZK identity policy kind");
  }
}

function policyParametersHash(policy: ZkIdentityPolicy): Hex {
  switch (policy.kind) {
    case "age-range":
      return keccak256(
        encodeAbiParameters(
          [{ type: "uint8" }, { type: "uint8" }, { type: "bool" }, { type: "uint32" }],
          [policy.minimumInclusive, policy.maximumExclusive ?? 0, policy.maximumExclusive !== null, packedDate(policy.referenceDate)],
        ),
      );
    case "country-set":
      return keccak256(
        encodeAbiParameters(
          [{ type: "uint8" }, { type: "uint8" }, { type: "bytes32" }, { type: "bytes32" }],
          [policy.attribute === "nationality" ? 1 : 2, policy.operator === "in" ? 1 : 2, keccak256(stringToBytes(policy.setId)), policy.setRoot],
        ),
      );
    case "document-validity":
      return keccak256(
        encodeAbiParameters(
          [{ type: "uint32" }, { type: "uint16" }],
          [packedDate(policy.referenceDate), policy.minimumRemainingDays],
        ),
      );
    case "document-authenticity":
      return keccak256(encodeAbiParameters([{ type: "uint8" }], [policy.minimumAssurance === "passive-auth" ? 1 : 2]));
    case "unique-human":
      return keccak256(
        encodeAbiParameters(
          [{ type: "bytes32" }, { type: "uint8" }],
          [keccak256(stringToBytes(policy.scope)), policy.nullifierMode === "single-use" ? 1 : 2],
        ),
      );
    case "dynamic-status":
      return keccak256(
        encodeAbiParameters(
          [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint32" }],
          [keccak256(stringToBytes(policy.status)), keccak256(stringToBytes(policy.providerId)), keccak256(stringToBytes(policy.listVersion)), policy.statusRoot, policy.maximumAgeSeconds],
        ),
      );
    case "private-field-match":
      return keccak256(
        encodeAbiParameters(
          [{ type: "bytes32" }, { type: "bytes32" }, { type: "bool" }],
          [keccak256(stringToBytes(policy.field)), policy.expectedCommitment, policy.consentRequired],
        ),
      );
  }
}

/** Hash a policy using a stable EVM ABI encoding. */
export function zkIdentityPolicyHash(input: ZkIdentityPolicy | ZkIdentityPolicyInput): Hex {
  const policy = normalizeZkIdentityPolicy(input);
  const kindHash = keccak256(stringToBytes(`${ZK_IDENTITY_POLICY_SCHEMA}:${policy.kind}`));
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint16" }, { type: "bytes32" }, { type: "bytes32" }],
      [policyDomainHash, ZK_IDENTITY_POLICY_VERSION, kindHash, policyParametersHash(policy)],
    ),
  );
}

/**
 * Produce the exact hashes and timestamp passed to
 * `ZkIdentityVersionRegistry.registerDynamicStatusPolicy`.
 *
 * The registry recomputes `policyHash`, preventing governance metadata from
 * drifting away from the canonical SDK policy committed by the circuit.
 */
export function dynamicStatusPolicyRegistration(input: {
  policy: DynamicStatusPolicy | DynamicStatusPolicyInput;
  publishedAt: number;
}): DynamicStatusPolicyRegistration {
  const policy = normalizeZkIdentityPolicy(input.policy);
  if (policy.kind !== "dynamic-status") throw new Error("dynamic status policy required");
  assertInteger(input.publishedAt, "dynamic status publication time", 1, 0xffffffff);
  return {
    policyHash: zkIdentityPolicyHash(policy),
    providerIdHash: keccak256(stringToBytes(policy.providerId)),
    listVersionHash: keccak256(stringToBytes(policy.listVersion)),
    statusRoot: policy.statusRoot,
    publishedAt: input.publishedAt,
    maximumAgeSeconds: policy.maximumAgeSeconds,
  };
}

/** JSON with schema-defined key order, useful for fixtures, developer tools and copy/paste. */
export function serializeZkIdentityPolicy(input: ZkIdentityPolicy | ZkIdentityPolicyInput): string {
  return JSON.stringify(normalizeZkIdentityPolicy(input), null, 2);
}

/** Commit to a versioned country list for demos/registries; members are sorted and deduplicated. */
export function countrySetCommitment(input: { setId: string; members: string[] }): Hex {
  const setId = assertIdentifier(input.setId, "country set id");
  const members = [...new Set(input.members.map((member) => member.trim().toUpperCase()))].sort();
  if (members.length === 0 || members.length > 256 || members.some((member) => !/^[A-Z]{3}$/u.test(member))) {
    throw new Error("country set must contain 1 to 256 ISO alpha-3 codes");
  }
  return keccak256(stringToBytes(`${ZK_IDENTITY_POLICY_SCHEMA}:country-set:${setId}:${members.join(",")}`));
}

/** Normalize and validate all public presentation bindings. */
export function normalizeZkPresentationBinding(input: ZkPresentationBindingInput): ZkPresentationBinding {
  if (!input || typeof input !== "object") throw new Error("ZK presentation binding must be an object");
  if (!Number.isSafeInteger(input.chainId) || input.chainId <= 0) throw new Error("chain id must be a positive integer");
  if (!isAddress(input.verifier) || !isAddress(input.consumer) || !isAddress(input.subject)) {
    throw new Error("verifier, consumer and subject must be EVM addresses");
  }
  assertInteger(input.epoch, "presentation epoch", 0, 0xffffffff);
  return {
    schema: ZK_PRESENTATION_SCHEMA,
    version: ZK_PRESENTATION_VERSION,
    policyHash: bytes32(input.policyHash, "policy hash"),
    chainId: input.chainId,
    verifier: getAddress(input.verifier),
    consumer: getAddress(input.consumer),
    subject: getAddress(input.subject),
    context: bytes32(input.context, "presentation context"),
    challenge: bytes32(input.challenge, "presentation challenge"),
    epoch: input.epoch,
  };
}

/** Hash the public EVM binding a holder proof must authenticate. */
export function zkPresentationBindingHash(input: ZkPresentationBindingInput): Hex {
  const binding = normalizeZkPresentationBinding(input);
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint16" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
        { type: "address" },
        { type: "address" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint32" },
      ],
      [
        presentationDomainHash,
        ZK_PRESENTATION_VERSION,
        binding.policyHash,
        BigInt(binding.chainId),
        binding.verifier,
        binding.consumer,
        binding.subject,
        binding.context,
        binding.challenge,
        binding.epoch,
      ],
    ),
  );
}
