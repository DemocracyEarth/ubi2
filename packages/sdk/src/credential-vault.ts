/**
 * Portable encrypted storage for a private identity credential.
 *
 * The credential is encrypted with a random 256-bit vault key. A WebAuthn PRF
 * result never encrypts the credential directly: it derives a wrapping key for
 * one key slot. Additional passkeys can wrap the same vault key, so the vault is
 * bound to the holder's key set rather than to one browser or physical device.
 *
 * This module deliberately stops below the WebAuthn ceremony. Applications must
 * obtain `prfOutput` from an authenticated credential whose raw id matches
 * `credentialId`, feature-detect the PRF extension, and validate decrypted
 * credential data against their own schema before using it.
 */

const FORMAT = "ubi2-private-credential" as const;
const VERSION = 1 as const;
const CIPHER = "A256GCM" as const;
const KEY_SLOT_TYPE = "webauthn-prf" as const;
const KDF = "HKDF-SHA-256" as const;
const AES_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const PRF_SALT_BYTES = 32;
const VAULT_ID_BYTES = 16;
const MAX_CREDENTIAL_BYTES = 256 * 1024;
const MAX_KEY_SLOTS = 16;

export interface CredentialVaultBinding {
  /** Versioned private-credential schema, for example `org.proofofhumanity.passport.v2`. */
  schema: string;
  /** WebAuthn relying-party id that is allowed to unlock this vault. */
  rpId: string;
}

export interface PasskeyKeySlot {
  version: typeof VERSION;
  type: typeof KEY_SLOT_TYPE;
  /** Base64url-encoded WebAuthn credential raw id. This value is public metadata. */
  credentialId: string;
  /** Base64url 32-byte input to the WebAuthn PRF extension. */
  prfSalt: string;
  kdf: typeof KDF;
  wrap: typeof CIPHER;
  iv: string;
  wrappedKey: string;
}

export interface PortableCredentialVault {
  format: typeof FORMAT;
  version: typeof VERSION;
  vaultId: string;
  binding: CredentialVaultBinding;
  payload: {
    cipher: typeof CIPHER;
    iv: string;
    ciphertext: string;
  };
  keySlots: PasskeyKeySlot[];
}

export interface PasskeyPrfEnrollment {
  /** Base64url-encoded `PublicKeyCredential.rawId`. */
  credentialId: string;
  /** The salt supplied to `extensions.prf.eval.first`. */
  prfSalt: string;
  /** The corresponding 32-byte `extensions.prf.results.first`. */
  prfOutput: Uint8Array;
}

export interface PasskeyPrfUnlock {
  credentialId: string;
  /** Freshly obtained PRF output for the salt stored in the matching key slot. */
  prfOutput: Uint8Array;
}

export type CredentialVaultPayloadTransform =
  | { status: "unchanged" }
  | { status: "updated"; payload: unknown };

export type CredentialVaultPayloadTransformResult =
  | { status: "unchanged" }
  | { status: "updated"; vault: PortableCredentialVault };

function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error("Web Crypto is required for the private credential vault");
  }
  return globalThis.crypto;
}

function asBuffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer as ArrayBuffer;
}

function randomBytes(length: number): Uint8Array {
  return webCrypto().getRandomValues(new Uint8Array(length));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function fromBase64Url(value: unknown, label: string, maxBytes = MAX_CREDENTIAL_BYTES + 16): Uint8Array {
  const maxEncodedLength = Math.ceil((maxBytes * 4) / 3) + 2;
  if (
    typeof value !== "string" ||
    value.length > maxEncodedLength ||
    !/^[A-Za-z0-9_-]+$/u.test(value) ||
    value.length % 4 === 1
  ) {
    throw new Error(`${label} must be unpadded base64url`);
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error(`${label} must be unpadded base64url`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  if (toBase64Url(bytes) !== value) throw new Error(`${label} must use canonical unpadded base64url`);
  return bytes;
}

function assertString(value: unknown, label: string, maxLength = 512): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new Error(`${label} must be a non-empty string of at most ${maxLength} characters`);
  }
}

function validateBinding(binding: CredentialVaultBinding): void {
  assertString(binding?.schema, "vault binding schema");
  assertString(binding?.rpId, "vault binding rpId", 253);
}

function payloadAad(vaultId: string, binding: CredentialVaultBinding): Uint8Array {
  return new TextEncoder().encode(JSON.stringify([FORMAT, VERSION, "payload", vaultId, binding.schema, binding.rpId]));
}

function slotAad(vaultId: string, slot: Pick<PasskeyKeySlot, "credentialId" | "prfSalt">): Uint8Array {
  return new TextEncoder().encode(JSON.stringify([FORMAT, VERSION, "key-slot", vaultId, slot.credentialId, slot.prfSalt]));
}

function validateEnrollment(enrollment: PasskeyPrfEnrollment): void {
  assertString(enrollment.credentialId, "WebAuthn credential id", 2048);
  fromBase64Url(enrollment.credentialId, "WebAuthn credential id", 1536);
  const salt = fromBase64Url(enrollment.prfSalt, "WebAuthn PRF salt", PRF_SALT_BYTES);
  if (salt.length !== PRF_SALT_BYTES) throw new Error(`WebAuthn PRF salt must be ${PRF_SALT_BYTES} bytes`);
  if (!(enrollment.prfOutput instanceof Uint8Array) || enrollment.prfOutput.length !== AES_KEY_BYTES) {
    throw new Error(`WebAuthn PRF output must be ${AES_KEY_BYTES} bytes`);
  }
}

function validateUnlock(unlock: PasskeyPrfUnlock): void {
  assertString(unlock.credentialId, "WebAuthn credential id", 2048);
  fromBase64Url(unlock.credentialId, "WebAuthn credential id", 1536);
  if (!(unlock.prfOutput instanceof Uint8Array) || unlock.prfOutput.length !== AES_KEY_BYTES) {
    throw new Error(`WebAuthn PRF output must be ${AES_KEY_BYTES} bytes`);
  }
}

/** Generate the 32-byte input to use as `extensions.prf.eval.first`. */
export function generatePasskeyPrfSalt(): string {
  return toBase64Url(randomBytes(PRF_SALT_BYTES));
}

/**
 * Parse and validate an untrusted serialized vault. This validates the envelope,
 * not the decrypted credential schema.
 */
export function parseCredentialVault(value: unknown): PortableCredentialVault {
  if (!value || typeof value !== "object") throw new Error("credential vault must be an object");
  const vault = value as Partial<PortableCredentialVault>;
  if (vault.format !== FORMAT || vault.version !== VERSION) throw new Error("unsupported credential vault format");
  assertString(vault.vaultId, "vault id", 64);
  if (fromBase64Url(vault.vaultId, "vault id", VAULT_ID_BYTES).length !== VAULT_ID_BYTES) {
    throw new Error(`vault id must be ${VAULT_ID_BYTES} bytes`);
  }
  if (!vault.binding || typeof vault.binding !== "object") throw new Error("vault binding is required");
  validateBinding(vault.binding);
  if (!vault.payload || typeof vault.payload !== "object" || vault.payload.cipher !== CIPHER) {
    throw new Error("unsupported credential vault cipher");
  }
  const payloadIv = fromBase64Url(vault.payload.iv, "payload iv", GCM_IV_BYTES);
  if (payloadIv.length !== GCM_IV_BYTES) throw new Error(`payload iv must be ${GCM_IV_BYTES} bytes`);
  const ciphertext = fromBase64Url(vault.payload.ciphertext, "credential ciphertext", MAX_CREDENTIAL_BYTES + 16);
  if (ciphertext.length < 16 || ciphertext.length > MAX_CREDENTIAL_BYTES + 16) {
    throw new Error("credential ciphertext has an invalid size");
  }
  if (!Array.isArray(vault.keySlots) || vault.keySlots.length === 0 || vault.keySlots.length > MAX_KEY_SLOTS) {
    throw new Error(`credential vault must contain between 1 and ${MAX_KEY_SLOTS} key slots`);
  }
  const credentialIds = new Set<string>();
  for (const slot of vault.keySlots) {
    if (
      !slot ||
      slot.version !== VERSION ||
      slot.type !== KEY_SLOT_TYPE ||
      slot.kdf !== KDF ||
      slot.wrap !== CIPHER
    ) {
      throw new Error("unsupported credential vault key slot");
    }
    assertString(slot.credentialId, "WebAuthn credential id", 2048);
    fromBase64Url(slot.credentialId, "WebAuthn credential id", 1536);
    if (credentialIds.has(slot.credentialId)) throw new Error("duplicate WebAuthn credential id");
    credentialIds.add(slot.credentialId);
    if (fromBase64Url(slot.prfSalt, "WebAuthn PRF salt", PRF_SALT_BYTES).length !== PRF_SALT_BYTES) {
      throw new Error(`WebAuthn PRF salt must be ${PRF_SALT_BYTES} bytes`);
    }
    if (fromBase64Url(slot.iv, "key-slot iv", GCM_IV_BYTES).length !== GCM_IV_BYTES) {
      throw new Error(`key-slot iv must be ${GCM_IV_BYTES} bytes`);
    }
    if (fromBase64Url(slot.wrappedKey, "wrapped vault key", AES_KEY_BYTES + 16).length !== AES_KEY_BYTES + 16) {
      throw new Error("wrapped vault key has an invalid size");
    }
  }
  return vault as PortableCredentialVault;
}

async function deriveWrappingKey(
  vaultId: string,
  credentialId: string,
  prfSalt: string,
  prfOutput: Uint8Array,
): Promise<CryptoKey> {
  const crypto = webCrypto();
  const material = await crypto.subtle.importKey("raw", asBuffer(prfOutput), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asBuffer(fromBase64Url(prfSalt, "WebAuthn PRF salt", PRF_SALT_BYTES)),
      info: asBuffer(slotAad(vaultId, { credentialId, prfSalt })),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptPayload(
  credential: unknown,
  vaultId: string,
  binding: CredentialVaultBinding,
  vaultKey: Uint8Array,
): Promise<PortableCredentialVault["payload"]> {
  let json: string | undefined;
  try {
    json = JSON.stringify(credential);
  } catch {
    throw new Error("private credential must be JSON-serializable");
  }
  if (json === undefined) throw new Error("private credential must be JSON-serializable");
  const plaintext = new TextEncoder().encode(json);
  if (plaintext.length === 0 || plaintext.length > MAX_CREDENTIAL_BYTES) {
    throw new Error(`private credential must be between 1 and ${MAX_CREDENTIAL_BYTES} bytes`);
  }
  const crypto = webCrypto();
  const key = await crypto.subtle.importKey("raw", asBuffer(vaultKey), { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = randomBytes(GCM_IV_BYTES);
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: asBuffer(iv), additionalData: asBuffer(payloadAad(vaultId, binding)), tagLength: 128 },
      key,
      asBuffer(plaintext),
    );
    return { cipher: CIPHER, iv: toBase64Url(iv), ciphertext: toBase64Url(new Uint8Array(ciphertext)) };
  } finally {
    plaintext.fill(0);
  }
}

async function appendKeySlot(
  vault: Omit<PortableCredentialVault, "keySlots"> & { keySlots: PasskeyKeySlot[] },
  vaultKey: Uint8Array,
  enrollment: PasskeyPrfEnrollment,
): Promise<PortableCredentialVault> {
  validateEnrollment(enrollment);
  if (vault.keySlots.length >= MAX_KEY_SLOTS) throw new Error("credential vault has reached the key-slot limit");
  if (vault.keySlots.some((slot) => slot.credentialId === enrollment.credentialId)) {
    throw new Error("this passkey already has a credential vault key slot");
  }
  const wrappingKey = await deriveWrappingKey(
    vault.vaultId,
    enrollment.credentialId,
    enrollment.prfSalt,
    enrollment.prfOutput,
  );
  const iv = randomBytes(GCM_IV_BYTES);
  const wrappedKey = await webCrypto().subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asBuffer(iv),
      additionalData: asBuffer(slotAad(vault.vaultId, enrollment)),
      tagLength: 128,
    },
    wrappingKey,
    asBuffer(vaultKey),
  );
  const slot: PasskeyKeySlot = {
    version: VERSION,
    type: KEY_SLOT_TYPE,
    credentialId: enrollment.credentialId,
    prfSalt: enrollment.prfSalt,
    kdf: KDF,
    wrap: CIPHER,
    iv: toBase64Url(iv),
    wrappedKey: toBase64Url(new Uint8Array(wrappedKey)),
  };
  return { ...vault, keySlots: [...vault.keySlots, slot] };
}

async function unwrapVaultKey(vault: PortableCredentialVault, unlock: PasskeyPrfUnlock): Promise<Uint8Array> {
  validateUnlock(unlock);
  const slot = vault.keySlots.find((candidate) => candidate.credentialId === unlock.credentialId);
  if (!slot) throw new Error("this passkey is not enrolled for the credential vault");
  const wrappingKey = await deriveWrappingKey(vault.vaultId, slot.credentialId, slot.prfSalt, unlock.prfOutput);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await webCrypto().subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asBuffer(fromBase64Url(slot.iv, "key-slot iv", GCM_IV_BYTES)),
        additionalData: asBuffer(slotAad(vault.vaultId, slot)),
        tagLength: 128,
      },
      wrappingKey,
      asBuffer(fromBase64Url(slot.wrappedKey, "wrapped vault key", AES_KEY_BYTES + 16)),
    );
  } catch {
    throw new Error("passkey could not unlock the credential vault");
  }
  const key = new Uint8Array(plaintext);
  if (key.length !== AES_KEY_BYTES) {
    key.fill(0);
    throw new Error("credential vault key has an invalid size");
  }
  return key;
}

async function decryptPayload(vault: PortableCredentialVault, vaultKey: Uint8Array): Promise<unknown> {
  const key = await webCrypto().subtle.importKey("raw", asBuffer(vaultKey), { name: "AES-GCM" }, false, ["decrypt"]);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await webCrypto().subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asBuffer(fromBase64Url(vault.payload.iv, "payload iv", GCM_IV_BYTES)),
        additionalData: asBuffer(payloadAad(vault.vaultId, vault.binding)),
        tagLength: 128,
      },
      key,
      asBuffer(fromBase64Url(vault.payload.ciphertext, "credential ciphertext", MAX_CREDENTIAL_BYTES + 16)),
    );
  } catch {
    throw new Error("credential vault authentication failed");
  }
  const bytes = new Uint8Array(plaintext);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } finally {
    bytes.fill(0);
  }
}

/** Create a new encrypted vault protected by one WebAuthn PRF-capable passkey. */
export async function createPasskeyProtectedCredentialVault(
  credential: unknown,
  binding: CredentialVaultBinding,
  enrollment: PasskeyPrfEnrollment,
): Promise<PortableCredentialVault> {
  validateBinding(binding);
  validateEnrollment(enrollment);
  const vaultBinding: CredentialVaultBinding = { schema: binding.schema, rpId: binding.rpId };
  const vaultKey = randomBytes(AES_KEY_BYTES);
  try {
    const vaultId = toBase64Url(randomBytes(VAULT_ID_BYTES));
    const payload = await encryptPayload(credential, vaultId, vaultBinding, vaultKey);
    return await appendKeySlot(
      { format: FORMAT, version: VERSION, vaultId, binding: vaultBinding, payload, keySlots: [] },
      vaultKey,
      enrollment,
    );
  } finally {
    vaultKey.fill(0);
  }
}

/** Unlock and decrypt a vault. The returned value is untrusted until the caller validates its schema. */
export async function unlockCredentialVault(vaultValue: unknown, unlock: PasskeyPrfUnlock): Promise<unknown> {
  const vault = parseCredentialVault(vaultValue);
  const vaultKey = await unwrapVaultKey(vault, unlock);
  try {
    return await decryptPayload(vault, vaultKey);
  } finally {
    vaultKey.fill(0);
  }
}

/**
 * Decrypt, transform and reseal a payload under the existing vault key.
 *
 * This is intended for isolated Workers. The callback must not retain, log or
 * transmit the decrypted value. An update replaces only the complete payload
 * ciphertext with a fresh AES-GCM IV; vault id, binding and key slots are kept
 * byte-for-byte semantically unchanged.
 */
export async function transformCredentialVaultPayload(
  vaultValue: unknown,
  unlock: PasskeyPrfUnlock,
  transform: (payload: unknown) => Promise<CredentialVaultPayloadTransform> | CredentialVaultPayloadTransform,
): Promise<CredentialVaultPayloadTransformResult> {
  if (typeof transform !== "function") throw new Error("credential vault transform callback is required");
  const vault = parseCredentialVault(vaultValue);
  const vaultKey = await unwrapVaultKey(vault, unlock);
  let payload: unknown;
  try {
    payload = await decryptPayload(vault, vaultKey);
    const transformed = await transform(payload);
    payload = undefined;
    if (!transformed || typeof transformed !== "object" || Array.isArray(transformed)) {
      throw new Error("credential vault transform returned an invalid result");
    }
    if (transformed.status === "unchanged" && Object.keys(transformed).length === 1) {
      return { status: "unchanged" };
    }
    if (transformed.status !== "updated" || Object.keys(transformed).sort().join(",") !== "payload,status") {
      throw new Error("credential vault transform returned an invalid result");
    }
    const replacement = await encryptPayload(transformed.payload, vault.vaultId, vault.binding, vaultKey);
    return { status: "updated", vault: { ...vault, payload: replacement } };
  } finally {
    payload = undefined;
    vaultKey.fill(0);
  }
}

/**
 * Add a second passkey without decrypting or re-encrypting the credential. The
 * existing passkey unwraps the vault key; the new PRF result creates another
 * independent key slot over that same key.
 */
export async function addPasskeyKeySlot(
  vaultValue: unknown,
  existingUnlock: PasskeyPrfUnlock,
  newEnrollment: PasskeyPrfEnrollment,
): Promise<PortableCredentialVault> {
  const vault = parseCredentialVault(vaultValue);
  const vaultKey = await unwrapVaultKey(vault, existingUnlock);
  try {
    return await appendKeySlot(vault, vaultKey, newEnrollment);
  } finally {
    vaultKey.fill(0);
  }
}
