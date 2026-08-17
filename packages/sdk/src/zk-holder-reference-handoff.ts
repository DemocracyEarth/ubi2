/**
 * Ephemeral holder-credential preparation and encrypted reference-vault handoff.
 *
 * Run this state machine inside a dedicated worker. Verified passport claims and
 * generated secrets exist only in that worker until `sealReferenceVault` encrypts
 * them. The resulting payload is explicitly reference-only: ADR-0012 forbids live
 * credential persistence until the production cryptographic profile is ratified.
 */
import { isHex, size, toHex, type Hex } from "viem";
import {
  createPasskeyProtectedCredentialVault,
  parseCredentialVault,
  unlockCredentialVault,
  type PasskeyPrfEnrollment,
  type PasskeyPrfUnlock,
  type PortableCredentialVault,
} from "./credential-vault";
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

export const ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA =
  "org.proofofhumanity.zk-holder-reference-vault-payload/1" as const;
export const ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_VERSION = 1 as const;
export const ZK_HOLDER_REFERENCE_PROFILE_STATUS = "reference-only-unratified" as const;
export const ZK_HOLDER_REFERENCE_WARNING =
  "research credential; production persistence and presentation are forbidden until cryptographic-profile ratification" as const;

const DEFAULT_SESSION_TTL_MS = 5 * 60 * 1_000;
const MAX_SESSION_TTL_MS = 10 * 60 * 1_000;
const RANDOM_SCALAR_ATTEMPTS = 256;
const SESSION_ID_BYTES = 16;
const UINT32_MAX = 0xffff_ffff;

/** Synthetic claim shape for reference integration. This object must never be logged or persisted. */
export interface ZkHolderReferenceClaims {
  issuerKeyId: Hex;
  statusId: number;
  dateOfBirth: string;
  nationality: string;
  issuingState: string;
  expiryDate: string;
  documentClass: PassportDocumentClass;
  assurance: PassportAssurance;
  issuedAtEpoch: number;
}

/** Exact decimal JSON accepted by the Rust/WASM holder-commitment builder. */
export interface ZkHolderReferencePrivateCredential {
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

/** Encrypted payload shape for synthetic/reference integration only; not a production wire contract. */
export interface ZkHolderReferenceVaultPayload {
  schema: typeof ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA;
  version: typeof ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_VERSION;
  profileStatus: typeof ZK_HOLDER_REFERENCE_PROFILE_STATUS;
  warning: typeof ZK_HOLDER_REFERENCE_WARNING;
  presentationReady: false;
  credential: ZkHolderReferencePrivateCredential;
  commitment: ZkHolderCredentialCommitment;
  issuanceTranscript: ZkHolderIssuanceTranscript;
}

export interface ZkHolderReferencePreparation {
  schema: "org.proofofhumanity.zk-holder-reference-preparation/1";
  sessionId: string;
  expiresAtMs: number;
  commitment: ZkHolderCredentialCommitment;
}

export type ZkHolderCommitmentBuilder = (privateInputJson: string) => Promise<unknown> | unknown;

export interface ZkHolderReferenceHandoffOptions {
  /** Trusted in-worker Rust/WASM export. Its errors are replaced with a non-sensitive error. */
  buildCommitment: ZkHolderCommitmentBuilder;
  /** Defaults to five minutes and may not exceed the original ten-minute authorization window. */
  sessionTtlMs?: number;
}

interface PendingSession {
  expiresAtMs: number;
  credential: ZkHolderReferencePrivateCredential;
  commitment: ZkHolderCredentialCommitment;
}

/**
 * One-at-a-time reference handoff for use inside a dedicated worker.
 *
 * A successful or binding-invalid seal consumes the session. Call `destroy` and
 * terminate the worker after completion or cancellation so immutable JS strings
 * do not outlive the ceremony through retained references.
 */
export class ZkHolderReferenceHandoff {
  readonly #buildCommitment: ZkHolderCommitmentBuilder;
  readonly #sessionTtlMs: number;
  readonly #sessions = new Map<string, PendingSession>();
  #preparing = false;
  #generation = 0;

  constructor(options: ZkHolderReferenceHandoffOptions) {
    if (!options || typeof options.buildCommitment !== "function") {
      throw new Error("a trusted holder commitment builder is required");
    }
    const ttl = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    if (!Number.isSafeInteger(ttl) || ttl < 1_000 || ttl > MAX_SESSION_TTL_MS) {
      throw new Error(`holder handoff session lifetime must be between 1000 and ${MAX_SESSION_TTL_MS} milliseconds`);
    }
    this.#buildCommitment = options.buildCommitment;
    this.#sessionTtlMs = ttl;
  }

  /** Generate holder material, invoke the trusted commitment builder, and retain claims only in memory. */
  async prepare(claims: ZkHolderReferenceClaims): Promise<ZkHolderReferencePreparation> {
    this.#purgeExpired();
    if (this.#preparing || this.#sessions.size !== 0) {
      throw new Error("holder handoff already has a pending credential session");
    }
    this.#preparing = true;
    const generation = this.#generation;
    let privateInputJson: string | undefined;
    try {
      const verifiedClaims = parseVerifiedClaims(claims);
      const holderSecret = randomNonZeroFieldElement();
      let credentialBlinding = randomNonZeroFieldElement();
      while (credentialBlinding === holderSecret) credentialBlinding = randomNonZeroFieldElement();

      const credential = normalizePrivateCredential({
        ...verifiedClaims,
        holderSecret: holderSecret.toString(),
        credentialBlinding: credentialBlinding.toString(),
      });
      privateInputJson = JSON.stringify(credential);

      let rawCommitment: unknown;
      try {
        rawCommitment = await this.#buildCommitment(privateInputJson);
      } catch {
        throw new Error("circuit-native holder commitment failed");
      }
      let commitment: ZkHolderCredentialCommitment;
      try {
        const value = typeof rawCommitment === "string" ? JSON.parse(rawCommitment) : rawCommitment;
        commitment = parseZkHolderCredentialCommitment(value);
      } catch {
        throw new Error("circuit-native holder commitment returned an invalid descriptor");
      }
      if (
        commitment.issuerKeyId !== credential.issuerKeyId ||
        commitment.statusId !== credential.statusId ||
        commitment.issuedAtEpoch !== credential.issuedAtEpoch
      ) {
        throw new Error("circuit-native holder commitment descriptor does not match the private input");
      }
      if (generation !== this.#generation) throw new Error("holder handoff was destroyed during preparation");

      const createdAtMs = this.#readClock();
      const expiresAtMs = createdAtMs + this.#sessionTtlMs;
      if (!Number.isSafeInteger(expiresAtMs)) throw new Error("holder handoff expiration is outside the safe range");
      const sessionId = this.#newSessionId();
      this.#sessions.set(sessionId, { expiresAtMs, credential, commitment });
      return {
        schema: "org.proofofhumanity.zk-holder-reference-preparation/1",
        sessionId,
        expiresAtMs,
        commitment,
      };
    } finally {
      privateInputJson = undefined;
      this.#preparing = false;
    }
  }

  /**
   * Bind the exact sanitized issuance transcript and return only authenticated ciphertext.
   * This reference artifact is for synthetic integration tests and cannot authorize a presentation.
   */
  async sealReferenceVault(input: {
    sessionId: string;
    issuanceTranscript: unknown;
    rpId: string;
    enrollment: PasskeyPrfEnrollment;
  }): Promise<PortableCredentialVault> {
    const transcript = parseZkHolderIssuanceTranscript(input.issuanceTranscript);
    const session = this.#takeSession(input.sessionId);
    if (!sameCommitment(session.commitment, transcript.commitment)) {
      throw new Error("issuance transcript does not match the pending holder commitment");
    }
    const payload = parseZkHolderReferenceVaultPayload({
      schema: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA,
      version: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_VERSION,
      profileStatus: ZK_HOLDER_REFERENCE_PROFILE_STATUS,
      warning: ZK_HOLDER_REFERENCE_WARNING,
      presentationReady: false,
      credential: session.credential,
      commitment: session.commitment,
      issuanceTranscript: transcript,
    });
    return createPasskeyProtectedCredentialVault(
      payload,
      { schema: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA, rpId: input.rpId },
      input.enrollment,
    );
  }

  /** Drop one pending session. Returns false for unknown, expired or malformed local ids. */
  abort(sessionId: string): boolean {
    this.#purgeExpired();
    if (!validSessionId(sessionId)) return false;
    return this.#sessions.delete(sessionId);
  }

  /** Drop all retained references and invalidate an in-flight preparation. */
  destroy(): void {
    this.#generation += 1;
    this.#sessions.clear();
  }

  #takeSession(sessionId: string): PendingSession {
    this.#purgeExpired();
    if (!validSessionId(sessionId)) throw new Error("holder handoff session id is invalid");
    const session = this.#sessions.get(sessionId);
    if (!session) throw new Error("holder handoff session is missing or expired");
    // Consume before encryption or further binding checks: retries require a fresh private commitment.
    this.#sessions.delete(sessionId);
    return session;
  }

  #purgeExpired(): void {
    const now = this.#readClock();
    for (const [sessionId, session] of this.#sessions) {
      if (session.expiresAtMs <= now) this.#sessions.delete(sessionId);
    }
  }

  #readClock(): number {
    const value = Date.now();
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("holder handoff clock is invalid");
    return value;
  }

  #newSessionId(): string {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const id = toBase64Url(randomBytes(SESSION_ID_BYTES));
      if (!this.#sessions.has(id)) return id;
    }
    throw new Error("could not allocate a unique holder handoff session");
  }
}

/** Strictly validate decrypted reference data before it reaches a prover or migration tool. */
export function parseZkHolderReferenceVaultPayload(value: unknown): ZkHolderReferenceVaultPayload {
  const candidate = object(value, "holder reference vault payload");
  exactKeys(
    candidate,
    [
      "schema",
      "version",
      "profileStatus",
      "warning",
      "presentationReady",
      "credential",
      "commitment",
      "issuanceTranscript",
    ],
    "holder reference vault payload",
  );
  if (
    candidate.schema !== ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA ||
    candidate.version !== ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_VERSION ||
    candidate.profileStatus !== ZK_HOLDER_REFERENCE_PROFILE_STATUS ||
    candidate.warning !== ZK_HOLDER_REFERENCE_WARNING ||
    candidate.presentationReady !== false
  ) {
    throw new Error("unsupported or presentation-enabled holder reference vault payload");
  }
  const credential = parsePrivateCredential(candidate.credential);
  const commitment = parseZkHolderCredentialCommitment(candidate.commitment);
  const issuanceTranscript = parseZkHolderIssuanceTranscript(candidate.issuanceTranscript);
  if (
    commitment.issuerKeyId !== credential.issuerKeyId ||
    commitment.statusId !== credential.statusId ||
    commitment.issuedAtEpoch !== credential.issuedAtEpoch ||
    !sameCommitment(commitment, issuanceTranscript.commitment)
  ) {
    throw new Error("holder reference vault payload bindings do not match");
  }
  return {
    schema: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA,
    version: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_VERSION,
    profileStatus: ZK_HOLDER_REFERENCE_PROFILE_STATUS,
    warning: ZK_HOLDER_REFERENCE_WARNING,
    presentationReady: false,
    credential,
    commitment,
    issuanceTranscript,
  };
}

/** Decrypt a reference vault in memory and validate its private schema and issuance bindings. */
export async function unlockZkHolderReferenceVault(
  vaultValue: unknown,
  unlock: PasskeyPrfUnlock,
): Promise<ZkHolderReferenceVaultPayload> {
  const vault = parseCredentialVault(vaultValue);
  if (vault.binding.schema !== ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA) {
    throw new Error("credential vault does not contain a holder reference payload");
  }
  return parseZkHolderReferenceVaultPayload(await unlockCredentialVault(vault, unlock));
}

function normalizePrivateCredential(
  input: ZkHolderReferenceClaims & { holderSecret: string; credentialBlinding: string },
): ZkHolderReferencePrivateCredential {
  const credential = {
    schema: ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA,
    issuerKeyId: normalizeBytes32(input.issuerKeyId, "issuer key id"),
    statusId: uint32(input.statusId, "credential status id", false),
    holderSecret: canonicalPrivateScalar(input.holderSecret, "holder secret"),
    credentialBlinding: canonicalPrivateScalar(input.credentialBlinding, "credential blinding"),
    dateOfBirth: input.dateOfBirth,
    nationality: country(input.nationality, "nationality"),
    issuingState: country(input.issuingState, "issuing state"),
    expiryDate: input.expiryDate,
    documentClass: input.documentClass,
    assurance: input.assurance,
    issuedAtEpoch: uint32(input.issuedAtEpoch, "credential issuance epoch", true),
  } as const;
  if (!syntheticCountry(credential.nationality) || !syntheticCountry(credential.issuingState)) {
    throw new Error("holder reference handoff accepts only XAA-XZZ synthetic country codes");
  }
  validatePrivateCredential(credential);
  return credential;
}

function parseVerifiedClaims(value: unknown): ZkHolderReferenceClaims {
  const candidate = object(value, "holder reference claims");
  exactKeys(
    candidate,
    [
      "issuerKeyId",
      "statusId",
      "dateOfBirth",
      "nationality",
      "issuingState",
      "expiryDate",
      "documentClass",
      "assurance",
      "issuedAtEpoch",
    ],
    "holder reference claims",
  );
  if (typeof candidate.dateOfBirth !== "string" || typeof candidate.expiryDate !== "string") {
    throw new Error("holder reference dates must be strings");
  }
  if (candidate.documentClass !== "epassport") throw new Error("unsupported holder document class");
  if (candidate.assurance !== "passive-auth" && candidate.assurance !== "chip-auth") {
    throw new Error("unsupported holder assurance class");
  }
  return {
    issuerKeyId: normalizeBytes32(candidate.issuerKeyId, "issuer key id"),
    statusId: uint32(candidate.statusId, "credential status id", false),
    dateOfBirth: candidate.dateOfBirth,
    nationality: country(candidate.nationality, "nationality"),
    issuingState: country(candidate.issuingState, "issuing state"),
    expiryDate: candidate.expiryDate,
    documentClass: candidate.documentClass,
    assurance: candidate.assurance,
    issuedAtEpoch: uint32(candidate.issuedAtEpoch, "credential issuance epoch", true),
  };
}

function parsePrivateCredential(value: unknown): ZkHolderReferencePrivateCredential {
  const candidate = object(value, "holder private credential");
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
    "holder private credential",
  );
  if (candidate.schema !== ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA) {
    throw new Error("unsupported holder private credential schema");
  }
  if (typeof candidate.dateOfBirth !== "string" || typeof candidate.expiryDate !== "string") {
    throw new Error("holder private credential dates must be strings");
  }
  if (candidate.documentClass !== "epassport") throw new Error("unsupported holder document class");
  if (candidate.assurance !== "passive-auth" && candidate.assurance !== "chip-auth") {
    throw new Error("unsupported holder assurance class");
  }
  return normalizePrivateCredential({
    issuerKeyId: normalizeBytes32(candidate.issuerKeyId, "issuer key id"),
    statusId: uint32(candidate.statusId, "credential status id", false),
    holderSecret: canonicalPrivateScalar(candidate.holderSecret, "holder secret"),
    credentialBlinding: canonicalPrivateScalar(candidate.credentialBlinding, "credential blinding"),
    dateOfBirth: candidate.dateOfBirth,
    nationality: strictCountry(candidate.nationality, "nationality"),
    issuingState: strictCountry(candidate.issuingState, "issuing state"),
    expiryDate: candidate.expiryDate,
    documentClass: candidate.documentClass,
    assurance: candidate.assurance,
    issuedAtEpoch: uint32(candidate.issuedAtEpoch, "credential issuance epoch", true),
  });
}

function validatePrivateCredential(input: ZkHolderReferencePrivateCredential): void {
  const privateInput: ZkPrivateCredentialInput = {
    issuerKeyId: input.issuerKeyId,
    statusId: toHex(input.statusId, { size: 32 }),
    holderSecret: BigInt(input.holderSecret),
    credentialBlinding: BigInt(input.credentialBlinding),
    dateOfBirth: input.dateOfBirth,
    nationality: input.nationality,
    issuingState: input.issuingState,
    expiryDate: input.expiryDate,
    documentClass: input.documentClass,
    assurance: input.assurance,
    issuedAtEpoch: input.issuedAtEpoch,
  };
  zkHolderCredentialFieldElements(privateInput);
}

function randomNonZeroFieldElement(): bigint {
  for (let attempt = 0; attempt < RANDOM_SCALAR_ATTEMPTS; attempt += 1) {
    const bytes = randomBytes(32);
    try {
      const value = BigInt(toHex(bytes));
      if (value > 0n && value < BN254_SCALAR_FIELD) return value;
    } finally {
      bytes.fill(0);
    }
  }
  throw new Error("platform CSPRNG did not produce a canonical holder field element");
}

function randomBytes(length: number): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) throw new Error("Web Crypto is required for holder material generation");
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function normalizeBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32 || BigInt(value) === 0n) {
    throw new Error(`${label} must be nonzero bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function canonicalPrivateScalar(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/u.test(value)) {
    throw new Error(`${label} must be a canonical nonzero decimal field element`);
  }
  const scalar = BigInt(value);
  if (scalar >= BN254_SCALAR_FIELD) {
    throw new Error(`${label} must be a canonical nonzero decimal field element`);
  }
  return value;
}

function country(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be an ISO alpha-3 code`);
  const normalized = value.trim().toUpperCase();
  if (!/^[A-Z]{3}$/u.test(normalized)) throw new Error(`${label} must be an ISO alpha-3 code`);
  return normalized;
}

function strictCountry(value: unknown, label: string): string {
  const normalized = country(value, label);
  if (value !== normalized) throw new Error(`${label} must use canonical uppercase ASCII`);
  return normalized;
}

function syntheticCountry(value: string): boolean {
  return /^X[A-Z]{2}$/u.test(value);
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

function validSessionId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{22}$/u.test(value);
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}
