import assert from "node:assert/strict";
import {
  addPasskeyKeySlot,
  createPasskeyProtectedCredentialVault,
  generatePasskeyPrfSalt,
  parseCredentialVault,
  unlockCredentialVault,
} from "./credential-vault";

const privateCredential = {
  schema: "org.proofofhumanity.passport.v2",
  holderSecret: "holder-secret-that-must-never-appear-in-public-metadata",
  passport: { nationality: "ARG", birthDate: "1990-01-01", expiryDate: "2032-07-18" },
  issuerSignature: "0x1234",
};
const binding = { schema: privateCredential.schema, rpId: "proofofhumanity.org" };
const credentialIdA = "cGFzc2tleS1jcmVkZW50aWFsLWE";
const credentialIdB = "cGFzc2tleS1jcmVkZW50aWFsLWI";
const prfOutputA = crypto.getRandomValues(new Uint8Array(32));
const prfOutputB = crypto.getRandomValues(new Uint8Array(32));

const vault = await createPasskeyProtectedCredentialVault(privateCredential, binding, {
  credentialId: credentialIdA,
  prfSalt: generatePasskeyPrfSalt(),
  prfOutput: prfOutputA,
});

assert.equal(vault.format, "ubi2-private-credential");
assert.equal(vault.version, 1);
assert.equal(vault.keySlots.length, 1);
assert.deepEqual(
  await unlockCredentialVault(vault, { credentialId: credentialIdA, prfOutput: prfOutputA }),
  privateCredential,
);

// The serializable envelope exposes binding and key-slot metadata, never plaintext attributes.
assert.deepEqual(Object.keys(vault).sort(), ["binding", "format", "keySlots", "payload", "vaultId", "version"]);
assert.deepEqual(Object.keys(vault.payload).sort(), ["cipher", "ciphertext", "iv"]);
assert.ok(vault.payload.ciphertext.length > 0);

await assert.rejects(
  unlockCredentialVault(vault, { credentialId: credentialIdA, prfOutput: crypto.getRandomValues(new Uint8Array(32)) }),
  /could not unlock/,
);
await assert.rejects(
  unlockCredentialVault(vault, { credentialId: credentialIdB, prfOutput: prfOutputB }),
  /not enrolled/,
);

const tamperedCiphertext = {
  ...vault,
  payload: {
    ...vault.payload,
    ciphertext: `${vault.payload.ciphertext[0] === "A" ? "B" : "A"}${vault.payload.ciphertext.slice(1)}`,
  },
};
await assert.rejects(
  unlockCredentialVault(tamperedCiphertext, { credentialId: credentialIdA, prfOutput: prfOutputA }),
  /authentication failed/,
);

const tamperedBinding = { ...vault, binding: { ...vault.binding, rpId: "attacker.example" } };
await assert.rejects(
  unlockCredentialVault(tamperedBinding, { credentialId: credentialIdA, prfOutput: prfOutputA }),
  /authentication failed/,
);

const portableVault = await addPasskeyKeySlot(
  vault,
  { credentialId: credentialIdA, prfOutput: prfOutputA },
  { credentialId: credentialIdB, prfSalt: generatePasskeyPrfSalt(), prfOutput: prfOutputB },
);
assert.equal(portableVault.keySlots.length, 2);
assert.deepEqual(
  await unlockCredentialVault(portableVault, { credentialId: credentialIdB, prfOutput: prfOutputB }),
  privateCredential,
);
assert.deepEqual(
  await unlockCredentialVault(portableVault, { credentialId: credentialIdA, prfOutput: prfOutputA }),
  privateCredential,
);
await assert.rejects(
  addPasskeyKeySlot(
    portableVault,
    { credentialId: credentialIdA, prfOutput: prfOutputA },
    { credentialId: credentialIdB, prfSalt: generatePasskeyPrfSalt(), prfOutput: prfOutputB },
  ),
  /already has/,
);

assert.deepEqual(parseCredentialVault(JSON.parse(JSON.stringify(portableVault))), portableVault);
assert.throws(() => parseCredentialVault({ ...portableVault, version: 2 }), /unsupported/);
assert.throws(
  () => parseCredentialVault({ ...portableVault, keySlots: [{ ...portableVault.keySlots[0], prfSalt: undefined }] }),
  /base64url/,
);

const secondVault = await createPasskeyProtectedCredentialVault(privateCredential, binding, {
  credentialId: credentialIdA,
  prfSalt: generatePasskeyPrfSalt(),
  prfOutput: prfOutputA,
});
assert.notEqual(secondVault.vaultId, vault.vaultId);
assert.notEqual(secondVault.payload.ciphertext, vault.payload.ciphertext);

console.log("credential vault: encrypted payload + tamper detection + multi-passkey unlock PASS");
