import assert from "node:assert/strict";
import {
  createPasskeyProtectedCredentialVault,
  generatePasskeyPrfSalt,
} from "@ubi2/sdk";
import {
  HOLDER_VAULT_BINDING_SCHEMA,
  HOLDER_VAULT_PRODUCT_PRODUCTION_APPROVED,
  HolderVaultSessionBoundary,
  createHolderVaultPayload,
  createHolderVaultRecoveryPackage,
  holderVaultBinding,
  holderVaultDatabaseName,
  holderVaultFeatureGate,
  parseHolderVaultPayload,
  parseHolderVaultRecoveryPackage,
} from "../app/lib/holder-vault-product";
import {
  encodeBase64Url,
  enrollWebAuthnPrfPasskey,
  unlockWithWebAuthnPrf,
  type WebAuthnPrfEnvironment,
} from "../app/lib/webauthn-prf";

async function main(): Promise<void> {
const ACCOUNT = "0x1111111111111111111111111111111111111111";
const OTHER_ACCOUNT = "0x2222222222222222222222222222222222222222";
const SESSION = "ab".repeat(16);

assert.deepEqual(
  holderVaultFeatureGate({ publicFlag: undefined, selfEnvironment: "staging", chainNetwork: "testnet" }),
  { visible: false, actionAllowed: false, reason: "The holder vault lab is disabled." },
);
assert.equal(holderVaultFeatureGate({ publicFlag: "true", selfEnvironment: "production", chainNetwork: "testnet" }).visible, false);
assert.deepEqual(
  holderVaultFeatureGate({ publicFlag: "true", selfEnvironment: "staging", chainNetwork: "mainnet" }),
  { visible: true, actionAllowed: false, reason: "Choose an explicitly classified public testnet." },
);
assert.equal(holderVaultFeatureGate({ publicFlag: "true", selfEnvironment: "staging", chainNetwork: "testnet" }).actionAllowed, true);
assert.equal(HOLDER_VAULT_PRODUCT_PRODUCTION_APPROVED, false);
assert.equal(HOLDER_VAULT_BINDING_SCHEMA, "org.proofofhumanity.v2-holder-pwa-testnet-vault/1");

const payload = await createHolderVaultPayload({
  account: ACCOUNT.toUpperCase().replace("0X", "0x"),
  verificationSession: SESSION,
  testnetChainId: 84532,
  proofBinding: "canonical-testnet-voucher",
});
assert.equal(payload.subjectAccount, ACCOUNT);
assert.equal(payload.productionEligible, false);
assert.match(payload.enrollmentSessionSha256, /^[0-9a-f]{64}$/u);
assert.match(payload.proofBindingSha256 ?? "", /^[0-9a-f]{64}$/u);
assert.equal(parseHolderVaultPayload(payload, ACCOUNT).testnetChainId, 84532);
assert.throws(() => parseHolderVaultPayload(payload, OTHER_ACCOUNT), /different credential account/u);
assert.throws(() => parseHolderVaultPayload({ ...payload, productionEligible: true }), /invalid/u);
assert.throws(() => parseHolderVaultPayload({ ...payload, extra: "field" }), /invalid/u);

const firstDatabase = await holderVaultDatabaseName(ACCOUNT, "example.test");
assert.equal(firstDatabase, await holderVaultDatabaseName(ACCOUNT, "example.test"));
assert.notEqual(firstDatabase, await holderVaultDatabaseName(OTHER_ACCOUNT, "example.test"));
assert.doesNotMatch(firstDatabase, /111111/u);

const boundary = new HolderVaultSessionBoundary(`${ACCOUNT}:${SESSION}`);
const firstSignal = boundary.signal;
const secret = boundary.track(new Uint8Array(32).fill(9));
boundary.rotate(`${OTHER_ACCOUNT}:${SESSION}`);
assert.equal(firstSignal.aborted, true);
assert.deepEqual(secret, new Uint8Array(32));
const cancelSignal = boundary.signal;
const cancelSecret = boundary.track(new Uint8Array(32).fill(7));
boundary.cancel();
assert.equal(cancelSignal.aborted, true);
assert.deepEqual(cancelSecret, new Uint8Array(32));

const rawId = new Uint8Array([1, 2, 3, 4]);
const output = new Uint8Array(32).fill(0x77);
let createCalls = 0;
let getCalls = 0;
const environment: WebAuthnPrfEnvironment = {
  secureContext: true,
  rpId: "example.test",
  crypto,
  credentials: {
    async create(options) {
      createCalls += 1;
      assert.equal(options?.publicKey?.rp.id, "example.test");
      assert.equal(options?.publicKey?.authenticatorSelection?.userVerification, "required");
      return credential(rawId, { prf: { enabled: true, results: { first: output.buffer } } });
    },
    async get(options) {
      getCalls += 1;
      assert.equal(options?.publicKey?.userVerification, "required");
      return credential(rawId, { prf: { results: { first: output.buffer } } });
    },
  },
};
const enrollment = await enrollWebAuthnPrfPasskey({ environment });
assert.equal(enrollment.credentialId, encodeBase64Url(rawId));
assert.deepEqual(enrollment.prfOutput, output);
assert.equal(createCalls, 1);
assert.equal(getCalls, 0);
const unlock = await unlockWithWebAuthnPrf({
  environment,
  slots: [{ credentialId: enrollment.credentialId, prfSalt: enrollment.prfSalt }],
});
assert.equal(unlock.credentialId, enrollment.credentialId);
assert.deepEqual(unlock.prfOutput, output);
assert.equal(getCalls, 1);

const fallbackEnvironment: WebAuthnPrfEnvironment = {
  ...environment,
  credentials: {
    async create() {
      return credential(rawId, { prf: { enabled: true } });
    },
    async get() {
      return credential(rawId, { prf: { results: { first: output.buffer } } });
    },
  },
};
assert.deepEqual((await enrollWebAuthnPrfPasskey({ environment: fallbackEnvironment })).prfOutput, output);

await assert.rejects(
  unlockWithWebAuthnPrf({
    environment: {
      ...environment,
      credentials: {
        ...environment.credentials,
        async get() { return credential(new Uint8Array([9]), { prf: { results: { first: output.buffer } } }); },
      },
    },
    slots: [{ credentialId: enrollment.credentialId, prfSalt: enrollment.prfSalt }],
  }),
  /not enrolled/u,
);
await assert.rejects(
  enrollWebAuthnPrfPasskey({ environment: { ...environment, secureContext: false } }),
  /secure HTTPS/u,
);

const vault = await createPasskeyProtectedCredentialVault(
  payload,
  holderVaultBinding("example.test"),
  { credentialId: enrollment.credentialId, prfSalt: generatePasskeyPrfSalt(), prfOutput: output },
);
const backup = {
  schema: "org.proofofhumanity.encrypted-credential-vault-backup/1" as const,
  version: 1 as const,
  cipher: "A256GCM" as const,
  kdf: "HKDF-SHA-256" as const,
  salt: encodeBase64Url(new Uint8Array(32).fill(1)),
  iv: encodeBase64Url(new Uint8Array(12).fill(2)),
  ciphertext: encodeBase64Url(new Uint8Array(17).fill(3)),
};
const recoveryPackage = createHolderVaultRecoveryPackage({ account: ACCOUNT, vault, backup });
assert.equal(parseHolderVaultRecoveryPackage(recoveryPackage, { account: ACCOUNT, rpId: "example.test" }).vaultId, vault.vaultId);
assert.throws(
  () => parseHolderVaultRecoveryPackage(recoveryPackage, { account: OTHER_ACCOUNT, rpId: "example.test" }),
  /different credential account/u,
);
assert.throws(
  () => parseHolderVaultRecoveryPackage(recoveryPackage, { account: ACCOUNT, rpId: "other.test" }),
  /another site/u,
);

console.log("holder vault product tests: ok");
}

void main();

function credential(rawIdValue: Uint8Array, extensions: unknown): Credential {
  return {
    id: encodeBase64Url(rawIdValue),
    type: "public-key",
    rawId: new Uint8Array(rawIdValue).buffer,
    getClientExtensionResults: () => extensions,
  } as unknown as Credential;
}
