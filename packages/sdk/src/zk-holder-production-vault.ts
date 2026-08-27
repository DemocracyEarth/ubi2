/**
 * Strict ADR-0014 production holder-vault plaintext contract.
 *
 * Parsing is intentionally separate from cryptographic verification. The
 * refresh/prover Worker must pass the parsed value to its locally bundled
 * Poseidon/Baby-Jubjub engine before treating it as usable.
 */
import { getAddress, isAddress, isHex, size, toHex, type Address, type Hex } from "viem";
import {
  parseZkHolderCredentialCommitment,
  parseZkHolderIssuanceTranscript,
  zkHolderCredentialFieldElements,
  ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA,
  type ZkHolderCredentialCommitment,
  type ZkHolderIssuanceTranscript,
} from "./zk-holder-credential";
import {
  BN254_SCALAR_FIELD,
  type PassportAssurance,
  type PassportDocumentClass,
  type ZkPrivateCredentialInput,
} from "./zk-identity-encoding";
import { ZK_HOLDER_PROFILE_ID } from "./zk-holder-profile-prover-worker";

export const ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA =
  "org.proofofhumanity.zk-holder-production-vault-payload/1" as const;
export const ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_VERSION = 1 as const;
export const ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256 =
  "b328af00b6d2cff39b5796b5abb37019dfaad5952fe23e10ba96913ab2a624bb" as const;
export const ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEMA =
  "org.proofofhumanity.zk-issuer-schnorr-artifact/1" as const;
export const ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEME =
  "schnorr-babyjubjub-poseidon-sha512-nonce/1" as const;
export const ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEMA =
  "org.proofofhumanity.zk-packed-status-witness/1" as const;
export const ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEME =
  "poseidon-bn254-packed-status-depth24/1" as const;

const BN254_BASE_FIELD =
  21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583n;
const BABY_JUBJUB_SUBGROUP_ORDER =
  2_736_030_358_979_909_402_780_800_718_157_159_386_076_813_972_158_567_259_200_215_660_948_447_373_041n;
const UINT32_MAX = 0xffff_ffff;
const UINT128_MAX = (1n << 128n) - 1n;

export interface ZkHolderProductionPrivateCredential {
  schema: typeof ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA;
  issuerKeyId: Hex;
  statusId: number;
  holderSecret: string;
  credentialBlinding: string;
  dateOfBirth: string;
  nationality: string;
  issuingState: string;
  expiryDate: string;
  documentClass: PassportDocumentClass;
  assurance: PassportAssurance;
  issuedAtEpoch: number;
}

export interface ZkHolderIssuerAuthentication {
  schema: typeof ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEMA;
  scheme: typeof ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEME;
  issuerKeyId: Hex;
  credentialCommitment: Hex;
  issuerPublicKey: { x: string; y: string };
  nonceCommitment: { x: string; y: string };
  responseScalar: string;
}

export interface ZkHolderPackedStatusWitness {
  schema: typeof ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEMA;
  scheme: typeof ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEME;
  issuerKeyId: Hex;
  statusId: number;
  snapshot: {
    chainId: string;
    issuanceRegistry: Address;
    snapshotId: number;
    root: Hex;
    activatedThroughStatusId: number;
    publishedAt: string;
  };
  chunkLimbsLittleEndian: [string, string];
  siblingsBottomUp: string[];
}

export interface ZkHolderProductionVaultPayload {
  schema: typeof ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA;
  version: typeof ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_VERSION;
  profile: {
    profileId: typeof ZK_HOLDER_PROFILE_ID;
    parameterManifestSha256: typeof ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256;
  };
  credential: ZkHolderProductionPrivateCredential;
  commitment: ZkHolderCredentialCommitment;
  issuerAuthentication: ZkHolderIssuerAuthentication;
  issuanceTranscript: ZkHolderIssuanceTranscript;
  statusWitness: ZkHolderPackedStatusWitness;
}

/** Strictly parse and cross-bind every non-cryptographic ADR-0014 invariant. */
export function parseZkHolderProductionVaultPayload(
  value: unknown,
): ZkHolderProductionVaultPayload {
  const candidate = object(value, "production holder vault payload");
  exactKeys(
    candidate,
    [
      "schema",
      "version",
      "profile",
      "credential",
      "commitment",
      "issuerAuthentication",
      "issuanceTranscript",
      "statusWitness",
    ],
    "production holder vault payload",
  );
  if (
    candidate.schema !== ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA ||
    candidate.version !== ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_VERSION
  ) {
    throw new Error("unsupported production holder vault payload");
  }
  const profile = parseProfile(candidate.profile);
  const credential = parsePrivateCredential(candidate.credential);
  const commitment = parseZkHolderCredentialCommitment(candidate.commitment);
  const issuerAuthentication = parseIssuerAuthentication(candidate.issuerAuthentication);
  const issuanceTranscript = parseZkHolderIssuanceTranscript(candidate.issuanceTranscript);
  const statusWitness = parseZkHolderPackedStatusWitness(candidate.statusWitness);

  if (
    credential.issuerKeyId !== commitment.issuerKeyId ||
    credential.statusId !== commitment.statusId ||
    credential.issuedAtEpoch !== commitment.issuedAtEpoch ||
    !sameCommitment(commitment, issuanceTranscript.commitment) ||
    issuerAuthentication.issuerKeyId !== commitment.issuerKeyId ||
    issuerAuthentication.credentialCommitment !== commitment.commitment ||
    statusWitness.issuerKeyId !== commitment.issuerKeyId ||
    statusWitness.statusId !== commitment.statusId
  ) {
    throw new Error("production holder vault credential bindings do not match");
  }
  if (
    statusWitness.snapshot.chainId !== issuanceTranscript.authorization.chainId ||
    statusWitness.snapshot.issuanceRegistry !== issuanceTranscript.authorization.issuanceRegistry ||
    statusWitness.snapshot.activatedThroughStatusId < credential.statusId
  ) {
    throw new Error("production holder vault status witness has the wrong issuance domain");
  }
  const initial = issuanceTranscript.statusSnapshot;
  if (initial === null) {
    throw new Error("production holder vault requires snapshot-covered issuance evidence");
  }
  if (
    statusWitness.snapshot.snapshotId < initial.snapshotId ||
    BigInt(statusWitness.snapshot.publishedAt) < BigInt(initial.publishedAt)
  ) {
    throw new Error("production holder vault status witness regressed from issuance");
  }
  if (
    statusWitness.snapshot.snapshotId === initial.snapshotId &&
    (
      statusWitness.snapshot.root !== initial.root ||
      statusWitness.snapshot.activatedThroughStatusId !== initial.activatedThroughStatusId ||
      statusWitness.snapshot.publishedAt !== initial.publishedAt
    )
  ) {
    throw new Error("production holder vault status witness equivocates at its snapshot id");
  }

  return {
    schema: ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA,
    version: ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_VERSION,
    profile,
    credential,
    commitment,
    issuerAuthentication,
    issuanceTranscript,
    statusWitness,
  };
}

/** Canonical semantic serialization used only inside the encrypted envelope. */
export function serializeZkHolderProductionVaultPayload(value: unknown): string {
  return JSON.stringify(parseZkHolderProductionVaultPayload(value));
}

export function parseZkHolderPackedStatusWitness(value: unknown): ZkHolderPackedStatusWitness {
  const candidate = object(value, "holder packed-status witness");
  exactKeys(
    candidate,
    ["schema", "scheme", "issuerKeyId", "statusId", "snapshot", "chunkLimbsLittleEndian", "siblingsBottomUp"],
    "holder packed-status witness",
  );
  if (
    candidate.schema !== ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEMA ||
    candidate.scheme !== ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEME
  ) {
    throw new Error("unsupported holder packed-status witness");
  }
  const issuerKeyId = bytes32(candidate.issuerKeyId, "status-witness issuer key id", true);
  const statusId = uint32(candidate.statusId, "status-witness status id", false);
  const snapshotCandidate = object(candidate.snapshot, "status-witness snapshot");
  exactKeys(
    snapshotCandidate,
    ["chainId", "issuanceRegistry", "snapshotId", "root", "activatedThroughStatusId", "publishedAt"],
    "status-witness snapshot",
  );
  const snapshot = {
    chainId: canonicalDecimal(snapshotCandidate.chainId, "status-witness chain id", false, (1n << 256n) - 1n),
    issuanceRegistry: address(snapshotCandidate.issuanceRegistry, "status-witness issuance registry"),
    snapshotId: uint32(snapshotCandidate.snapshotId, "status-witness snapshot id", false),
    root: fieldBytes32(snapshotCandidate.root, "status-witness root", true),
    activatedThroughStatusId: uint32(
      snapshotCandidate.activatedThroughStatusId,
      "status-witness allocation watermark",
      true,
    ),
    publishedAt: canonicalDecimal(snapshotCandidate.publishedAt, "status-witness publication time", false, BigInt(UINT32_MAX)),
  };
  if (snapshot.activatedThroughStatusId < statusId) {
    throw new Error("status-witness snapshot does not cover the private slot");
  }
  if (!Array.isArray(candidate.chunkLimbsLittleEndian) || candidate.chunkLimbsLittleEndian.length !== 2) {
    throw new Error("status-witness chunk must contain exactly two limbs");
  }
  const chunkLimbsLittleEndian = candidate.chunkLimbsLittleEndian.map((limb, index) =>
    canonicalDecimal(limb, `status-witness chunk limb ${index}`, true, UINT128_MAX),
  ) as [string, string];
  const chunk = BigInt(chunkLimbsLittleEndian[0]) | (BigInt(chunkLimbsLittleEndian[1]) << 128n);
  if (((chunk >> BigInt(statusId & 0xff)) & 1n) !== 0n) {
    throw new Error("status-witness private slot is not active");
  }
  if (!Array.isArray(candidate.siblingsBottomUp) || candidate.siblingsBottomUp.length !== 24) {
    throw new Error("status-witness path must contain exactly 24 siblings");
  }
  const siblingsBottomUp = candidate.siblingsBottomUp.map((sibling, index) =>
    canonicalDecimal(sibling, `status-witness sibling ${index}`, true, BN254_SCALAR_FIELD - 1n),
  );
  return {
    schema: ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEMA,
    scheme: ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEME,
    issuerKeyId,
    statusId,
    snapshot,
    chunkLimbsLittleEndian,
    siblingsBottomUp,
  };
}

function parseProfile(value: unknown): ZkHolderProductionVaultPayload["profile"] {
  const candidate = object(value, "production holder profile");
  exactKeys(candidate, ["profileId", "parameterManifestSha256"], "production holder profile");
  if (
    candidate.profileId !== ZK_HOLDER_PROFILE_ID ||
    candidate.parameterManifestSha256 !== ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256
  ) {
    throw new Error("production holder profile is not the ratified profile");
  }
  return {
    profileId: ZK_HOLDER_PROFILE_ID,
    parameterManifestSha256: ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  };
}

function parsePrivateCredential(value: unknown): ZkHolderProductionPrivateCredential {
  const candidate = object(value, "production holder private credential");
  exactKeys(
    candidate,
    [
      "schema",
      "issuerKeyId",
      "statusId",
      "holderSecret",
      "credentialBlinding",
      "dateOfBirth",
      "nationality",
      "issuingState",
      "expiryDate",
      "documentClass",
      "assurance",
      "issuedAtEpoch",
    ],
    "production holder private credential",
  );
  if (candidate.schema !== ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA) {
    throw new Error("unsupported production holder private credential");
  }
  if (typeof candidate.dateOfBirth !== "string" || typeof candidate.expiryDate !== "string") {
    throw new Error("production holder credential dates must be strings");
  }
  if (candidate.documentClass !== "epassport") throw new Error("unsupported holder document class");
  if (candidate.assurance !== "passive-auth" && candidate.assurance !== "chip-auth") {
    throw new Error("unsupported holder assurance class");
  }
  const credential: ZkHolderProductionPrivateCredential = {
    schema: ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA,
    issuerKeyId: bytes32(candidate.issuerKeyId, "credential issuer key id", true),
    statusId: uint32(candidate.statusId, "credential status id", false),
    holderSecret: canonicalDecimal(candidate.holderSecret, "holder secret", false, BN254_SCALAR_FIELD - 1n),
    credentialBlinding: canonicalDecimal(
      candidate.credentialBlinding,
      "credential blinding",
      false,
      BN254_SCALAR_FIELD - 1n,
    ),
    dateOfBirth: candidate.dateOfBirth,
    nationality: country(candidate.nationality, "nationality"),
    issuingState: country(candidate.issuingState, "issuing state"),
    expiryDate: candidate.expiryDate,
    documentClass: candidate.documentClass,
    assurance: candidate.assurance,
    issuedAtEpoch: uint32(candidate.issuedAtEpoch, "credential issuance epoch", true),
  };
  const circuitInput: ZkPrivateCredentialInput = {
    issuerKeyId: credential.issuerKeyId,
    statusId: toHex(credential.statusId, { size: 32 }),
    holderSecret: BigInt(credential.holderSecret),
    credentialBlinding: BigInt(credential.credentialBlinding),
    dateOfBirth: credential.dateOfBirth,
    nationality: credential.nationality,
    issuingState: credential.issuingState,
    expiryDate: credential.expiryDate,
    documentClass: credential.documentClass,
    assurance: credential.assurance,
    issuedAtEpoch: credential.issuedAtEpoch,
  };
  zkHolderCredentialFieldElements(circuitInput);
  return credential;
}

function parseIssuerAuthentication(value: unknown): ZkHolderIssuerAuthentication {
  const candidate = object(value, "holder issuer authentication");
  exactKeys(
    candidate,
    [
      "schema",
      "scheme",
      "issuerKeyId",
      "credentialCommitment",
      "issuerPublicKey",
      "nonceCommitment",
      "responseScalar",
    ],
    "holder issuer authentication",
  );
  if (
    candidate.schema !== ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEMA ||
    candidate.scheme !== ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEME
  ) {
    throw new Error("unsupported holder issuer authentication");
  }
  return {
    schema: ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEMA,
    scheme: ZK_HOLDER_ISSUER_AUTHENTICATION_SCHEME,
    issuerKeyId: bytes32(candidate.issuerKeyId, "issuer authentication key id", true),
    credentialCommitment: fieldBytes32(
      candidate.credentialCommitment,
      "issuer credential commitment",
      true,
    ),
    issuerPublicKey: point(candidate.issuerPublicKey, "issuer public key"),
    nonceCommitment: point(candidate.nonceCommitment, "issuer nonce commitment"),
    responseScalar: canonicalDecimal(
      candidate.responseScalar,
      "issuer response scalar",
      true,
      BABY_JUBJUB_SUBGROUP_ORDER - 1n,
    ),
  };
}

function point(value: unknown, label: string): { x: string; y: string } {
  const candidate = object(value, label);
  exactKeys(candidate, ["x", "y"], label);
  const result = {
    x: canonicalDecimal(candidate.x, `${label} x`, true, BN254_BASE_FIELD - 1n),
    y: canonicalDecimal(candidate.y, `${label} y`, true, BN254_BASE_FIELD - 1n),
  };
  if (BigInt(result.x) === 0n && BigInt(result.y) === 0n) throw new Error(`${label} must not be zero`);
  return result;
}

function sameCommitment(left: ZkHolderCredentialCommitment, right: ZkHolderCredentialCommitment): boolean {
  return (
    left.schema === right.schema &&
    left.credentialSchema === right.credentialSchema &&
    left.commitmentScheme === right.commitmentScheme &&
    left.issuerKeyId === right.issuerKeyId &&
    left.statusId === right.statusId &&
    left.issuedAtEpoch === right.issuedAtEpoch &&
    left.commitment === right.commitment
  );
}

function exactKeys(candidate: Record<string, unknown>, keys: readonly string[], label: string): void {
  const expected = [...keys].sort();
  const actual = Object.keys(candidate).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function bytes32(value: unknown, label: string, nonZero = false): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (nonZero && BigInt(normalized) === 0n) throw new Error(`${label} must not be zero`);
  return normalized;
}

function fieldBytes32(value: unknown, label: string, nonZero = false): Hex {
  const normalized = bytes32(value, label, nonZero);
  if (BigInt(normalized) >= BN254_SCALAR_FIELD) {
    throw new Error(`${label} must be a canonical BN254 field element`);
  }
  return normalized;
}

function address(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a nonzero EVM address`);
  }
  return getAddress(value);
}

function uint32(value: unknown, label: string, allowZero: boolean): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1) ||
    value > UINT32_MAX
  ) {
    throw new Error(`${label} must be ${allowZero ? "a" : "a nonzero"} uint32`);
  }
  return value;
}

function canonicalDecimal(
  value: unknown,
  label: string,
  allowZero: boolean,
  maximum: bigint,
): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed = BigInt(value);
  if ((!allowZero && parsed === 0n) || parsed > maximum) {
    throw new Error(`${label} is outside the supported range`);
  }
  return value;
}

function country(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Z]{3}$/u.test(value)) {
    throw new Error(`${label} must be an uppercase ISO alpha-3 code`);
  }
  return value;
}
