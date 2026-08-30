import type { PasskeyKeySlot, PasskeyPrfEnrollment, PasskeyPrfUnlock } from "@ubi2/sdk";

const PRF_BYTES = 32;
const CEREMONY_TIMEOUT_MS = 120_000;

interface PrfExtensionResults {
  prf?: {
    enabled?: boolean;
    results?: { first?: ArrayBuffer | ArrayBufferView };
  };
}

interface PublicKeyCredentialLike extends Credential {
  rawId: ArrayBuffer;
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
}

export interface WebAuthnPrfEnvironment {
  credentials: Pick<CredentialsContainer, "create" | "get">;
  crypto: Pick<Crypto, "getRandomValues">;
  rpId: string;
  secureContext: boolean;
}

export interface WebAuthnPrfCapabilities {
  available: boolean;
  prfClientHint: "supported" | "unsupported" | "unknown";
  platformAuthenticator: boolean | null;
}

/** Browser hints improve copy only; every ceremony still verifies an actual 32-byte PRF result. */
export async function inspectWebAuthnPrfCapabilities(): Promise<WebAuthnPrfCapabilities> {
  const Constructor = globalThis.PublicKeyCredential as typeof PublicKeyCredential & {
    getClientCapabilities?: () => Promise<Record<string, boolean>>;
  };
  if (!Constructor || !globalThis.navigator?.credentials) {
    return { available: false, prfClientHint: "unsupported", platformAuthenticator: false };
  }
  let prfClientHint: WebAuthnPrfCapabilities["prfClientHint"] = "unknown";
  if (typeof Constructor.getClientCapabilities === "function") {
    try {
      const capabilities = await Constructor.getClientCapabilities();
      prfClientHint = capabilities["extension:prf"] === true ? "supported" : "unsupported";
    } catch {
      prfClientHint = "unknown";
    }
  }
  let platformAuthenticator: boolean | null = null;
  try {
    platformAuthenticator = await Constructor.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    platformAuthenticator = null;
  }
  return { available: true, prfClientHint, platformAuthenticator };
}

export function browserWebAuthnPrfEnvironment(rpId = globalThis.location?.hostname ?? ""): WebAuthnPrfEnvironment {
  return {
    credentials: globalThis.navigator.credentials,
    crypto: globalThis.crypto,
    rpId,
    secureContext: globalThis.isSecureContext,
  };
}

/** Enroll one user-verified passkey and prove that its PRF extension actually evaluates. */
export async function enrollWebAuthnPrfPasskey(input: {
  environment?: WebAuthnPrfEnvironment;
  excludeCredentialIds?: readonly string[];
  signal?: AbortSignal;
} = {}): Promise<PasskeyPrfEnrollment> {
  const environment = checkedEnvironment(input.environment ?? browserWebAuthnPrfEnvironment());
  const prfSaltBytes = random(environment.crypto, PRF_BYTES);
  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: { id: environment.rpId, name: "Proof of Humanity" },
    user: {
      id: arrayBuffer(random(environment.crypto, 32)),
      name: "private-holder-vault",
      displayName: "Proof of Humanity testnet vault",
    },
    challenge: arrayBuffer(random(environment.crypto, 32)),
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -8 },
    ],
    timeout: CEREMONY_TIMEOUT_MS,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      requireResidentKey: false,
      userVerification: "required",
    },
    excludeCredentials: (input.excludeCredentialIds ?? []).map((credentialId) => ({
      id: arrayBuffer(decodeBase64Url(credentialId, "WebAuthn credential id")),
      type: "public-key" as const,
    })),
    extensions: { prf: { eval: { first: arrayBuffer(prfSaltBytes) } } } as AuthenticationExtensionsClientInputs,
  };

  try {
    const created = credentialLike(await environment.credentials.create({ publicKey, signal: input.signal }));
    const credentialId = encodeBase64Url(new Uint8Array(created.rawId));
    const registration = prfResult(created);
    if (registration.output) {
      return { credentialId, prfSalt: encodeBase64Url(prfSaltBytes), prfOutput: registration.output };
    }
    if (registration.enabled !== true) throw new Error("This passkey does not support the WebAuthn PRF extension.");
    const assertion = await evaluatePrf({
      environment,
      slots: [{ credentialId, prfSalt: encodeBase64Url(prfSaltBytes) }],
      signal: input.signal,
    });
    return { credentialId, prfSalt: encodeBase64Url(prfSaltBytes), prfOutput: assertion.prfOutput };
  } finally {
    prfSaltBytes.fill(0);
  }
}

/** Ask any enrolled credential for the PRF value belonging to its own key slot. */
export async function unlockWithWebAuthnPrf(input: {
  slots: readonly Pick<PasskeyKeySlot, "credentialId" | "prfSalt">[];
  environment?: WebAuthnPrfEnvironment;
  signal?: AbortSignal;
}): Promise<PasskeyPrfUnlock> {
  if (!Array.isArray(input.slots) || input.slots.length === 0) throw new Error("No passkey is enrolled for this vault.");
  return evaluatePrf({
    environment: checkedEnvironment(input.environment ?? browserWebAuthnPrfEnvironment()),
    slots: input.slots,
    signal: input.signal,
  });
}

async function evaluatePrf(input: {
  environment: WebAuthnPrfEnvironment;
  slots: readonly Pick<PasskeyKeySlot, "credentialId" | "prfSalt">[];
  signal?: AbortSignal;
}): Promise<PasskeyPrfUnlock> {
  const salts = input.slots.map(({ credentialId, prfSalt }) => ({
    credentialId,
    bytes: decodeBase64Url(prfSalt, "WebAuthn PRF salt"),
  }));
  const extensions = input.slots.length === 1
    ? { prf: { eval: { first: arrayBuffer(salts[0]!.bytes) } } }
    : {
        prf: {
          evalByCredential: Object.fromEntries(
            salts.map(({ credentialId, bytes }) => [credentialId, { first: arrayBuffer(bytes) }]),
          ),
        },
      };
  try {
    const asserted = credentialLike(await input.environment.credentials.get({
      publicKey: {
        challenge: arrayBuffer(random(input.environment.crypto, 32)),
        rpId: input.environment.rpId,
        timeout: CEREMONY_TIMEOUT_MS,
        userVerification: "required",
        allowCredentials: input.slots.map(({ credentialId }) => ({
          id: arrayBuffer(decodeBase64Url(credentialId, "WebAuthn credential id")),
          type: "public-key" as const,
        })),
        extensions: extensions as AuthenticationExtensionsClientInputs,
      },
      signal: input.signal,
    }));
    const credentialId = encodeBase64Url(new Uint8Array(asserted.rawId));
    if (!input.slots.some((slot) => slot.credentialId === credentialId)) {
      throw new Error("The authenticator returned a passkey that is not enrolled for this vault.");
    }
    const result = prfResult(asserted);
    if (!result.output) throw new Error("The passkey did not return a WebAuthn PRF result.");
    return { credentialId, prfOutput: result.output };
  } finally {
    for (const { bytes } of salts) bytes.fill(0);
  }
}

function checkedEnvironment(environment: WebAuthnPrfEnvironment): WebAuthnPrfEnvironment {
  if (!environment?.secureContext) throw new Error("Passkeys require a secure HTTPS context.");
  if (!environment.credentials?.create || !environment.credentials?.get) throw new Error("WebAuthn is not available in this browser.");
  if (!environment.crypto?.getRandomValues) throw new Error("Web Crypto is not available in this browser.");
  const rpId = environment.rpId.trim().toLowerCase();
  if (!rpId || rpId.length > 253 || rpId.includes(":") || rpId.includes("/") || /\s/u.test(rpId)) {
    throw new Error("The WebAuthn relying-party id is invalid.");
  }
  return { ...environment, rpId };
}

function credentialLike(value: Credential | null): PublicKeyCredentialLike {
  const credential = value as Partial<PublicKeyCredentialLike> | null;
  if (
    !credential ||
    credential.type !== "public-key" ||
    !(credential.rawId instanceof ArrayBuffer) ||
    typeof credential.getClientExtensionResults !== "function"
  ) {
    throw new Error("The browser did not return a valid public-key credential.");
  }
  return credential as PublicKeyCredentialLike;
}

function prfResult(credential: PublicKeyCredentialLike): { enabled?: boolean; output?: Uint8Array } {
  const results = credential.getClientExtensionResults() as PrfExtensionResults;
  const first = results.prf?.results?.first;
  if (first === undefined) return { enabled: results.prf?.enabled };
  const bytes = ArrayBuffer.isView(first)
    ? new Uint8Array(first.buffer, first.byteOffset, first.byteLength)
    : new Uint8Array(first);
  if (bytes.byteLength !== PRF_BYTES) throw new Error(`WebAuthn PRF output must be ${PRF_BYTES} bytes.`);
  return { enabled: results.prf?.enabled, output: new Uint8Array(bytes) };
}

function random(crypto: Pick<Crypto, "getRandomValues">, length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer as ArrayBuffer;
}

export function encodeBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

export function decodeBase64Url(value: unknown, label: string, maxBytes = 2048): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil((maxBytes * 4) / 3) + 2 ||
    !/^[A-Za-z0-9_-]+$/u.test(value) ||
    value.length % 4 === 1
  ) {
    throw new Error(`${label} must be canonical unpadded base64url.`);
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let decoded: string;
  try {
    decoded = atob(padded);
  } catch {
    throw new Error(`${label} must be canonical unpadded base64url.`);
  }
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (bytes.byteLength > maxBytes || encodeBase64Url(bytes) !== value) {
    throw new Error(`${label} must be canonical unpadded base64url.`);
  }
  return bytes;
}
