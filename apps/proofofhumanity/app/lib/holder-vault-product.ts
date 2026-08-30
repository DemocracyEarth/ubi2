import {
  parseEncryptedCredentialVaultBackup,
  type CredentialVaultBinding,
  type EncryptedCredentialVaultBackup,
  type PortableCredentialVault,
} from "@ubi2/sdk";
import type { Address } from "viem";
import { decodeBase64Url, encodeBase64Url } from "./webauthn-prf";

export const HOLDER_VAULT_PAYLOAD_SCHEMA = "org.proofofhumanity.v2-holder-pwa-testnet-rehearsal/1" as const;
export const HOLDER_VAULT_RECOVERY_SCHEMA = "org.proofofhumanity.v2-holder-pwa-recovery-package/1" as const;
export const HOLDER_VAULT_BINDING_SCHEMA = "org.proofofhumanity.v2-holder-pwa-testnet-vault/1" as const;
export const HOLDER_VAULT_PRODUCT_PRODUCTION_APPROVED = false as const;

export interface HolderVaultPayload {
  schema: typeof HOLDER_VAULT_PAYLOAD_SCHEMA;
  version: 1;
  productionEligible: false;
  subjectAccount: Address;
  enrollmentSessionSha256: string;
  testnetChainId: number;
  proofBindingSha256: string | null;
}

export interface HolderVaultRecoveryPackage {
  schema: typeof HOLDER_VAULT_RECOVERY_SCHEMA;
  version: 1;
  productionEligible: false;
  subjectAccount: Address;
  vaultId: string;
  binding: CredentialVaultBinding;
  backup: EncryptedCredentialVaultBackup;
}

export function holderVaultFeatureGate(input: {
  publicFlag: string | undefined;
  selfEnvironment: string;
  chainNetwork?: "local" | "testnet" | "mainnet";
}): { visible: boolean; actionAllowed: boolean; reason: string } {
  const visible = input.publicFlag === "true" && input.selfEnvironment === "staging";
  if (!visible) return { visible: false, actionAllowed: false, reason: "The holder vault lab is disabled." };
  if (input.chainNetwork !== undefined && input.chainNetwork !== "testnet") {
    return { visible: true, actionAllowed: false, reason: "Choose an explicitly classified public testnet." };
  }
  return { visible: true, actionAllowed: true, reason: "Testnet rehearsal only." };
}

export function holderVaultBinding(rpId: string): CredentialVaultBinding {
  const normalized = checkedRpId(rpId);
  return { schema: HOLDER_VAULT_BINDING_SCHEMA, rpId: normalized };
}

export async function holderVaultDatabaseName(accountValue: string, rpIdValue: string): Promise<string> {
  const account = checkedAccount(accountValue);
  const rpId = checkedRpId(rpIdValue);
  const input = new TextEncoder().encode(JSON.stringify(["poh-holder-vault", 1, account, rpId]));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  input.fill(0);
  return `poh-holder-vault-${Array.from(digest.slice(0, 16), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export async function createHolderVaultPayload(input: {
  account: string;
  verificationSession: string;
  testnetChainId: number;
  proofBinding?: string | null;
}): Promise<HolderVaultPayload> {
  const account = checkedAccount(input.account);
  if (!/^[0-9a-f]{32}$/u.test(input.verificationSession)) throw new Error("Holder vault session must be 128-bit lowercase hex.");
  if (!Number.isSafeInteger(input.testnetChainId) || input.testnetChainId <= 0) throw new Error("Holder vault testnet chain id is invalid.");
  return {
    schema: HOLDER_VAULT_PAYLOAD_SCHEMA,
    version: 1,
    productionEligible: false,
    subjectAccount: account,
    enrollmentSessionSha256: await sha256Hex(input.verificationSession),
    testnetChainId: input.testnetChainId,
    proofBindingSha256: input.proofBinding ? await sha256Hex(input.proofBinding) : null,
  };
}

export function parseHolderVaultPayload(value: unknown, expectedAccount?: string): HolderVaultPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Holder vault payload is invalid.");
  const candidate = value as Partial<HolderVaultPayload>;
  if (
    Object.keys(candidate).sort().join(",") !==
      "enrollmentSessionSha256,productionEligible,proofBindingSha256,schema,subjectAccount,testnetChainId,version" ||
    candidate.schema !== HOLDER_VAULT_PAYLOAD_SCHEMA ||
    candidate.version !== 1 ||
    candidate.productionEligible !== false ||
    typeof candidate.enrollmentSessionSha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(candidate.enrollmentSessionSha256) ||
    (candidate.proofBindingSha256 !== null &&
      (typeof candidate.proofBindingSha256 !== "string" || !/^[0-9a-f]{64}$/u.test(candidate.proofBindingSha256))) ||
    !Number.isSafeInteger(candidate.testnetChainId) ||
    (candidate.testnetChainId as number) <= 0
  ) {
    throw new Error("Holder vault payload is invalid.");
  }
  const subjectAccount = checkedAccount(candidate.subjectAccount);
  if (expectedAccount !== undefined && subjectAccount !== checkedAccount(expectedAccount)) {
    throw new Error("The unlocked vault belongs to a different credential account.");
  }
  return { ...candidate, subjectAccount } as HolderVaultPayload;
}

export function createHolderVaultRecoveryPackage(input: {
  account: string;
  vault: PortableCredentialVault;
  backup: EncryptedCredentialVaultBackup;
}): HolderVaultRecoveryPackage {
  return {
    schema: HOLDER_VAULT_RECOVERY_SCHEMA,
    version: 1,
    productionEligible: false,
    subjectAccount: checkedAccount(input.account),
    vaultId: input.vault.vaultId,
    binding: { ...input.vault.binding },
    backup: parseEncryptedCredentialVaultBackup(input.backup),
  };
}

export function parseHolderVaultRecoveryPackage(value: unknown, expected: {
  account: string;
  rpId: string;
}): HolderVaultRecoveryPackage {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Holder vault recovery package is invalid.");
  const candidate = value as Partial<HolderVaultRecoveryPackage>;
  if (
    Object.keys(candidate).sort().join(",") !==
      "backup,binding,productionEligible,schema,subjectAccount,vaultId,version" ||
    candidate.schema !== HOLDER_VAULT_RECOVERY_SCHEMA ||
    candidate.version !== 1 ||
    candidate.productionEligible !== false ||
    typeof candidate.vaultId !== "string" ||
    !candidate.binding ||
    candidate.binding.schema !== HOLDER_VAULT_BINDING_SCHEMA ||
    candidate.binding.rpId !== checkedRpId(expected.rpId)
  ) {
    throw new Error("Holder vault recovery package is invalid or belongs to another site.");
  }
  const subjectAccount = checkedAccount(candidate.subjectAccount);
  if (subjectAccount !== checkedAccount(expected.account)) {
    throw new Error("The recovery package belongs to a different credential account.");
  }
  decodeBase64Url(candidate.vaultId, "vault id", 16);
  return {
    schema: HOLDER_VAULT_RECOVERY_SCHEMA,
    version: 1,
    productionEligible: false,
    subjectAccount,
    vaultId: candidate.vaultId,
    binding: { ...candidate.binding },
    backup: parseEncryptedCredentialVaultBackup(candidate.backup),
  };
}

export function encodeHolderVaultRecoveryKey(key: Uint8Array): string {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) throw new Error("Holder vault recovery key must be 32 bytes.");
  return encodeBase64Url(key);
}

export function decodeHolderVaultRecoveryKey(value: string): Uint8Array {
  const key = decodeBase64Url(value.trim(), "Holder vault recovery key", 32);
  if (key.byteLength !== 32) throw new Error("Holder vault recovery key must be 32 bytes.");
  return key;
}

/** Abort stale ceremonies and zero every tracked byte buffer on an account/session change. */
export class HolderVaultSessionBoundary {
  #binding: string;
  #controller = new AbortController();
  readonly #secrets = new Set<Uint8Array>();

  constructor(binding: string) {
    this.#binding = checkedSessionBinding(binding);
  }

  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  rotate(binding: string): void {
    const next = checkedSessionBinding(binding);
    if (next === this.#binding) return;
    this.#invalidate();
    this.#binding = next;
    this.#controller = new AbortController();
  }

  cancel(): void {
    this.#invalidate();
    this.#controller = new AbortController();
  }

  track(secret: Uint8Array): Uint8Array {
    if (!(secret instanceof Uint8Array)) throw new Error("Only byte secrets can cross the holder session boundary.");
    this.#secrets.add(secret);
    return secret;
  }

  release(secret: Uint8Array): void {
    secret.fill(0);
    this.#secrets.delete(secret);
  }

  close(): void {
    this.#invalidate();
  }

  #invalidate(): void {
    this.#controller.abort();
    for (const secret of this.#secrets) secret.fill(0);
    this.#secrets.clear();
  }
}

function checkedSessionBinding(value: string): string {
  if (typeof value !== "string" || value.length < 16 || value.length > 512) throw new Error("Holder vault session binding is invalid.");
  return value;
}

function checkedAccount(value: unknown): Address {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) throw new Error("Holder vault account is invalid.");
  return value.toLowerCase() as Address;
}

function checkedRpId(value: string): string {
  const rpId = value.trim().toLowerCase();
  if (!rpId || rpId.length > 253 || rpId.includes(":") || rpId.includes("/") || /\s/u.test(rpId)) {
    throw new Error("Holder vault relying-party id is invalid.");
  }
  return rpId;
}

async function sha256Hex(value: string): Promise<string> {
  if (value.length > 16_384) throw new Error("Holder vault binding input is too large.");
  const bytes = new TextEncoder().encode(value);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  bytes.fill(0);
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
