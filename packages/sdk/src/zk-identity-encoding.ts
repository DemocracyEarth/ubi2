/**
 * Canonical v2 private-credential, nullifier-scope and public-signal encodings.
 *
 * This module pins field order and EVM ABI semantics across TypeScript, Solidity
 * and Rust. It deliberately does not select the circuit-native hash used for
 * credential authentication or nullifier derivation; those choices remain
 * behind the Stage 1 measurement gate in ADR-0010.
 */
import {
  concatHex,
  encodeAbiParameters,
  getAddress,
  isAddress,
  isHex,
  keccak256,
  size,
  stringToBytes,
  stringToHex,
  toHex,
  type Address,
  type Hex,
} from "viem";

export const ZK_PRIVATE_CREDENTIAL_SCHEMA = "org.proofofhumanity.zk-private-credential" as const;
export const ZK_PRIVATE_CREDENTIAL_VERSION = 1 as const;
export const ZK_NULLIFIER_SCOPE_SCHEMA = "org.proofofhumanity.zk-nullifier-scope" as const;
export const ZK_NULLIFIER_SCOPE_VERSION = 1 as const;
export const ZK_PUBLIC_SIGNALS_SCHEMA = "org.proofofhumanity.zk-public-signals" as const;
export const ZK_PUBLIC_SIGNALS_VERSION = 1 as const;

/** BN254 scalar-field order. Circuit-visible field elements must be strictly below it. */
export const BN254_SCALAR_FIELD =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;

export type PassportDocumentClass = "epassport";
export type PassportAssurance = "passive-auth" | "chip-auth";
export type ZkNullifierMode = "single-use" | "stable-pseudonym";

export interface ZkPrivateCredentialInput {
  /** Registry identifier for the credential authentication key. */
  issuerKeyId: Hex;
  /** Private status-leaf identifier; never expose it in a presentation. */
  statusId: Hex;
  /** Holder-generated, non-zero BN254 field element. */
  holderSecret: bigint;
  /** Independent, non-zero BN254 field element hiding equal credential data. */
  credentialBlinding: bigint;
  dateOfBirth: string;
  nationality: string;
  issuingState: string;
  expiryDate: string;
  documentClass: PassportDocumentClass;
  assurance: PassportAssurance;
  issuedAtEpoch: number;
}

export interface ZkNullifierScopeInput {
  mode: ZkNullifierMode;
  chainId: number;
  verifier: Address;
  consumer: Address;
  context: Hex;
  policyHash: Hex;
}

export interface ZkIdentityPublicSignalValues {
  circuitId: Hex;
  issuerKeyId: Hex;
  activeRoot: Hex;
  policyHash: Hex;
  presentationBindingHash: Hex;
  nullifierScopeHash: Hex;
  scopedNullifier: bigint;
  subject: Address;
  result: boolean;
  credentialEpoch: number;
  /** Unix snapshot-publication time in seconds; zero means no dynamic-status policy. */
  statusEpoch: number;
}

/** Application context consumed by the governed EVM predicate-prover adapter. */
export interface ZkPredicateProofContextInput {
  /** Stable consumer action/scope identifier; challenge is kept separate. */
  context: Hex;
  /** Fresh non-zero challenge selected by the consumer. */
  challenge: Hex;
  nullifierMode: ZkNullifierMode;
}

/** Fixed v1 public-signal layout. A changed order is a new layout version. */
export const ZK_PUBLIC_SIGNAL_INDEX = {
  layoutVersion: 0,
  circuitIdHi: 1,
  circuitIdLo: 2,
  issuerKeyIdHi: 3,
  issuerKeyIdLo: 4,
  activeRootHi: 5,
  activeRootLo: 6,
  policyHashHi: 7,
  policyHashLo: 8,
  presentationBindingHashHi: 9,
  presentationBindingHashLo: 10,
  nullifierScopeHashHi: 11,
  nullifierScopeHashLo: 12,
  scopedNullifier: 13,
  subject: 14,
  result: 15,
  credentialEpoch: 16,
  statusEpoch: 17,
} as const;
export const ZK_PUBLIC_SIGNAL_COUNT = 18 as const;

const credentialDomainHash = keccak256(stringToBytes(ZK_PRIVATE_CREDENTIAL_SCHEMA));
const nullifierScopeDomainHash = keccak256(stringToBytes(ZK_NULLIFIER_SCOPE_SCHEMA));
const nullifierPreimageDomainHash = keccak256(
  stringToBytes(`${ZK_NULLIFIER_SCOPE_SCHEMA}:derive`),
);
const UINT128_MAX = (1n << 128n) - 1n;
const UINT160_MAX = (1n << 160n) - 1n;

function assertInteger(value: number, label: string, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
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

function fieldElement(value: bigint, label: string, allowZero = false): bigint {
  if (typeof value !== "bigint" || value < 0n || value >= BN254_SCALAR_FIELD || (!allowZero && value === 0n)) {
    throw new Error(`${label} must be ${allowZero ? "a" : "a non-zero"} canonical BN254 field element`);
  }
  return value;
}

function civilDate(value: string, label: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(value);
  if (!match) throw new Error(`${label} must use YYYY-MM-DD`);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    year < 1900 ||
    year > 2500 ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new Error(`${label} must be a valid civil date from 1900 through 2500`);
  }
  return value;
}

function packedDate(value: string): number {
  return Number(value.replaceAll("-", ""));
}

function countryCode(value: string, label: string): Hex {
  const normalized = value.trim().toUpperCase();
  if (!/^[A-Z]{3}$/u.test(normalized)) throw new Error(`${label} must be an ISO alpha-3 code`);
  return stringToHex(normalized, { size: 3 });
}

function nullifierModeCode(mode: ZkNullifierMode): 1 | 2 {
  if (mode === "single-use") return 1;
  if (mode === "stable-pseudonym") return 2;
  throw new Error("unsupported nullifier mode");
}

function normalizeAddress(value: Address, label: string): Address {
  if (!isAddress(value)) throw new Error(`${label} must be an EVM address`);
  const normalized = getAddress(value);
  if (BigInt(normalized) === 0n) throw new Error(`${label} must not be the zero address`);
  return normalized;
}

/**
 * Canonical EVM encoding of the private credential fields authenticated at issuance.
 *
 * The resulting bytes contain private data and must only exist inside the encrypted
 * vault or an isolated prover. Do not log, transmit, or persist them in plaintext.
 */
export function encodeZkPrivateCredential(input: ZkPrivateCredentialInput): Hex {
  const dateOfBirth = civilDate(input.dateOfBirth, "date of birth");
  const expiryDate = civilDate(input.expiryDate, "expiry date");
  if (packedDate(expiryDate) <= packedDate(dateOfBirth)) {
    throw new Error("expiry date must be after date of birth");
  }
  if (input.documentClass !== "epassport") throw new Error("unsupported document class");
  if (input.assurance !== "passive-auth" && input.assurance !== "chip-auth") {
    throw new Error("unsupported passport assurance");
  }
  assertInteger(input.issuedAtEpoch, "credential issuance epoch", 0, 0xffffffff);

  return encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "uint16" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint32" },
      { type: "bytes3" },
      { type: "bytes3" },
      { type: "uint32" },
      { type: "uint8" },
      { type: "uint8" },
      { type: "uint32" },
    ],
    [
      credentialDomainHash,
      ZK_PRIVATE_CREDENTIAL_VERSION,
      nonZeroBytes32(input.issuerKeyId, "issuer key id"),
      nonZeroBytes32(input.statusId, "credential status id"),
      fieldElement(input.holderSecret, "holder secret"),
      fieldElement(input.credentialBlinding, "credential blinding"),
      packedDate(dateOfBirth),
      countryCode(input.nationality, "nationality"),
      countryCode(input.issuingState, "issuing state"),
      packedDate(expiryDate),
      1,
      input.assurance === "passive-auth" ? 1 : 2,
      input.issuedAtEpoch,
    ],
  );
}

/**
 * Diagnostic cross-language fingerprint of the canonical private encoding.
 *
 * This is not the ratified SNARK-native credential commitment and must never be
 * exposed as a presentation identifier.
 */
export function zkPrivateCredentialFingerprint(input: ZkPrivateCredentialInput): Hex {
  return keccak256(encodeZkPrivateCredential(input));
}

/**
 * Consumer scope for nullifier derivation. Challenge, subject and epoch are
 * intentionally excluded: changing them must not create another one-per-scope slot.
 */
export function zkNullifierScopeHash(input: ZkNullifierScopeInput): Hex {
  if (!Number.isSafeInteger(input.chainId) || input.chainId <= 0) {
    throw new Error("chain id must be a positive integer");
  }
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint16" },
        { type: "uint8" },
        { type: "uint256" },
        { type: "address" },
        { type: "address" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        nullifierScopeDomainHash,
        ZK_NULLIFIER_SCOPE_VERSION,
        nullifierModeCode(input.mode),
        BigInt(input.chainId),
        normalizeAddress(input.verifier, "verifier"),
        normalizeAddress(input.consumer, "consumer"),
        bytes32(input.context, "nullifier context"),
        nonZeroBytes32(input.policyHash, "policy hash"),
      ],
    ),
  );
}

/**
 * Encode the application context accepted by ZkIdentityPredicateProver.
 *
 * PredicateVerifier itself wraps these bytes with the actual consuming address
 * before calling the prover, so clients must not add a consumer envelope.
 */
export function encodeZkPredicateProofContext(input: ZkPredicateProofContextInput): Hex {
  return encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }],
    [
      bytes32(input.context, "predicate proof context"),
      nonZeroBytes32(input.challenge, "predicate proof challenge"),
      nullifierModeCode(input.nullifierMode),
    ],
  );
}

/** Losslessly split bytes32 into two circuit-safe 128-bit limbs, most-significant first. */
export function splitBytes32(value: Hex): readonly [bigint, bigint] {
  const normalized = BigInt(bytes32(value, "bytes32 value"));
  return [normalized >> 128n, normalized & UINT128_MAX] as const;
}

/** Recombine two canonical 128-bit limbs without field reduction. */
export function joinBytes32(high: bigint, low: bigint): Hex {
  if (high < 0n || high > UINT128_MAX || low < 0n || low > UINT128_MAX) {
    throw new Error("bytes32 limbs must be unsigned 128-bit integers");
  }
  return toHex((high << 128n) | low, { size: 32 });
}

/**
 * Ordered circuit inputs for scoped-nullifier derivation.
 *
 * A Stage 1 candidate hash (for example Poseidon) consumes these six canonical
 * field elements. Pinning this preimage does not pre-select that hash function.
 */
export function zkScopedNullifierPreimage(
  holderSecret: bigint,
  scope: ZkNullifierScopeInput,
): readonly [bigint, bigint, bigint, bigint, bigint, bigint] {
  const [domainHi, domainLo] = splitBytes32(nullifierPreimageDomainHash);
  const [scopeHi, scopeLo] = splitBytes32(zkNullifierScopeHash(scope));
  return [
    domainHi,
    domainLo,
    BigInt(ZK_NULLIFIER_SCOPE_VERSION),
    fieldElement(holderSecret, "holder secret"),
    scopeHi,
    scopeLo,
  ] as const;
}

/** Encode the fixed, lossless v1 circuit public-signal vector. */
export function encodeZkIdentityPublicSignals(input: ZkIdentityPublicSignalValues): readonly bigint[] {
  const [circuitHi, circuitLo] = splitBytes32(nonZeroBytes32(input.circuitId, "circuit id"));
  const [issuerHi, issuerLo] = splitBytes32(nonZeroBytes32(input.issuerKeyId, "issuer key id"));
  const [rootHi, rootLo] = splitBytes32(nonZeroBytes32(input.activeRoot, "active credential root"));
  const [policyHi, policyLo] = splitBytes32(nonZeroBytes32(input.policyHash, "policy hash"));
  const [bindingHi, bindingLo] = splitBytes32(
    nonZeroBytes32(input.presentationBindingHash, "presentation binding hash"),
  );
  const [scopeHi, scopeLo] = splitBytes32(
    nonZeroBytes32(input.nullifierScopeHash, "nullifier scope hash"),
  );
  const subject = BigInt(normalizeAddress(input.subject, "subject"));
  assertInteger(input.credentialEpoch, "credential epoch", 0, 0xffffffff);
  assertInteger(input.statusEpoch, "status epoch", 0, 0xffffffff);

  return [
    BigInt(ZK_PUBLIC_SIGNALS_VERSION),
    circuitHi,
    circuitLo,
    issuerHi,
    issuerLo,
    rootHi,
    rootLo,
    policyHi,
    policyLo,
    bindingHi,
    bindingLo,
    scopeHi,
    scopeLo,
    fieldElement(input.scopedNullifier, "scoped nullifier"),
    subject,
    input.result ? 1n : 0n,
    BigInt(input.credentialEpoch),
    BigInt(input.statusEpoch),
  ] as const;
}

/** Decode and strictly validate the fixed v1 public-signal vector. */
export function decodeZkIdentityPublicSignals(signals: readonly bigint[]): ZkIdentityPublicSignalValues {
  if (signals.length !== ZK_PUBLIC_SIGNAL_COUNT) {
    throw new Error(`expected ${ZK_PUBLIC_SIGNAL_COUNT} ZK identity public signals`);
  }
  for (const [index, signal] of signals.entries()) {
    fieldElement(signal, `public signal ${index}`, true);
  }
  if (signals[ZK_PUBLIC_SIGNAL_INDEX.layoutVersion] !== BigInt(ZK_PUBLIC_SIGNALS_VERSION)) {
    throw new Error("unsupported ZK identity public-signal layout");
  }
  if (signals[ZK_PUBLIC_SIGNAL_INDEX.subject] > UINT160_MAX) {
    throw new Error("public subject exceeds 160 bits");
  }
  if (signals[ZK_PUBLIC_SIGNAL_INDEX.subject] === 0n) {
    throw new Error("public subject must not be the zero address");
  }
  if (signals[ZK_PUBLIC_SIGNAL_INDEX.result] > 1n) {
    throw new Error("public result must be zero or one");
  }
  if (
    signals[ZK_PUBLIC_SIGNAL_INDEX.credentialEpoch] > 0xffffffffn ||
    signals[ZK_PUBLIC_SIGNAL_INDEX.statusEpoch] > 0xffffffffn
  ) {
    throw new Error("public epoch exceeds uint32");
  }

  const identifiers = [
    [signals[1], signals[2], "circuit id"],
    [signals[3], signals[4], "issuer key id"],
    [signals[5], signals[6], "active credential root"],
    [signals[7], signals[8], "policy hash"],
    [signals[9], signals[10], "presentation binding hash"],
    [signals[11], signals[12], "nullifier scope hash"],
  ] as const;
  for (const [high, low, label] of identifiers) {
    if (high > UINT128_MAX || low > UINT128_MAX) {
      throw new Error(`${label} limbs must be unsigned 128-bit integers`);
    }
    if (high === 0n && low === 0n) throw new Error(`${label} must not be zero`);
  }

  return {
    circuitId: joinBytes32(signals[1], signals[2]),
    issuerKeyId: joinBytes32(signals[3], signals[4]),
    activeRoot: joinBytes32(signals[5], signals[6]),
    policyHash: joinBytes32(signals[7], signals[8]),
    presentationBindingHash: joinBytes32(signals[9], signals[10]),
    nullifierScopeHash: joinBytes32(signals[11], signals[12]),
    scopedNullifier: fieldElement(signals[13], "scoped nullifier"),
    subject: getAddress(toHex(signals[14], { size: 20 })),
    result: signals[15] === 1n,
    credentialEpoch: Number(signals[16]),
    statusEpoch: Number(signals[17]),
  };
}

/** Byte representation used by fixture generators and prover-worker messages. */
export function serializeZkIdentityPublicSignals(signals: readonly bigint[]): Hex {
  const decoded = decodeZkIdentityPublicSignals(signals);
  void decoded;
  return concatHex(signals.map((signal) => toHex(signal, { size: 32 })));
}
