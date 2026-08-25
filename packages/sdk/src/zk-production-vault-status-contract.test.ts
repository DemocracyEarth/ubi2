import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseZkHolderIssuanceTranscript } from "./zk-holder-credential";

const repository = fileURLToPath(new URL("../../..", import.meta.url));

async function json(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(`${repository}/${path}`, "utf8")) as Record<string, unknown>;
}

function record(value: unknown, label: string): Record<string, unknown> {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label} field set drifted`);
}

function collectKeys(value: unknown, output = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, output);
  } else if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      output.add(key);
      collectKeys(nested, output);
    }
  }
  return output;
}

function fieldHex(value: unknown): string {
  return `0x${BigInt(String(value)).toString(16).padStart(64, "0")}`;
}

const [contract, reference, signalManifest, frozenInterface, artifactIndex] = await Promise.all([
  json("fixtures/v2-identity/production-vault-status-v1.json"),
  json("fixtures/v2-production-crypto/reference-vector-v1.json"),
  json("fixtures/v2-production-crypto/public-signals-v1.json"),
  json("fixtures/v2-identity/interface-v1.json"),
  json("fixtures/v2-production-crypto/artifact-index-v1.json"),
]);

assert.equal(contract.schema, "org.proofofhumanity.v2-production-vault-status-contract-vector/1");
assert.match(String(contract.warning), /synthetic/u);

const payload = record(contract.payload, "production payload");
exactKeys(
  payload,
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
  "production payload",
);
assert.equal(payload.schema, "org.proofofhumanity.zk-holder-production-vault-payload/1");
assert.equal(payload.version, 1);

const profile = record(payload.profile, "profile");
exactKeys(profile, ["profileId", "parameterManifestSha256"], "profile");
assert.equal(profile.profileId, reference.profileId);
const parameterBytes = await readFile(
  `${repository}/fixtures/v2-production-crypto/parameters-v1.json`,
);
const parameterDigest = createHash("sha256").update(parameterBytes).digest("hex");
assert.equal(profile.parameterManifestSha256, parameterDigest);
const indexedParameter = (artifactIndex.artifacts as Array<Record<string, unknown>>).find(
  ({ path }) => path === "fixtures/v2-production-crypto/parameters-v1.json",
);
assert.equal(indexedParameter?.sha256, parameterDigest, "vault must pin the admitted parameter artifact");

const credential: Record<string, unknown> = record(payload.credential, "credential");
const expectedCredential: Record<string, unknown> = {
  schema: "org.proofofhumanity.zk-holder-credential-input/1",
  ...record(reference.privateSyntheticCredential, "reference credential"),
};
assert.deepEqual(credential, expectedCredential);

const commitment = record(payload.commitment, "commitment");
assert.equal(commitment.issuerKeyId, credential.issuerKeyId);
assert.equal(commitment.statusId, credential.statusId);
assert.equal(commitment.issuedAtEpoch, credential.issuedAtEpoch);
assert.equal(commitment.commitment, fieldHex(reference.credentialCommitment));

const referenceIssuer = record(reference.issuerAuthentication, "reference issuer artifact");
const issuer = record(payload.issuerAuthentication, "issuer artifact");
exactKeys(
  issuer,
  [
    "schema",
    "scheme",
    "issuerKeyId",
    "credentialCommitment",
    "issuerPublicKey",
    "nonceCommitment",
    "responseScalar",
  ],
  "issuer artifact",
);
assert.equal(issuer.schema, "org.proofofhumanity.zk-issuer-schnorr-artifact/1");
assert.equal(issuer.scheme, "schnorr-babyjubjub-poseidon-sha512-nonce/1");
assert.equal(issuer.issuerKeyId, referenceIssuer.issuerKeyId);
assert.equal(issuer.credentialCommitment, commitment.commitment);
assert.deepEqual(issuer.issuerPublicKey, referenceIssuer.issuerPublicKey);
assert.deepEqual(issuer.nonceCommitment, referenceIssuer.R);
assert.equal(issuer.responseScalar, referenceIssuer.responseScalar);

const transcript = parseZkHolderIssuanceTranscript(payload.issuanceTranscript);
assert.deepEqual(transcript.commitment, commitment);
assert.equal(transcript.authorization.chainId, "84532");
assert.equal(transcript.allocation.statusId, credential.statusId);
assert.equal(transcript.allocation.issuedAtEpoch, credential.issuedAtEpoch);

const witness = record(payload.statusWitness, "status witness");
exactKeys(
  witness,
  [
    "schema",
    "scheme",
    "issuerKeyId",
    "statusId",
    "snapshot",
    "chunkLimbsLittleEndian",
    "siblingsBottomUp",
  ],
  "status witness",
);
assert.equal(witness.schema, "org.proofofhumanity.zk-packed-status-witness/1");
assert.equal(witness.scheme, "poseidon-bn254-packed-status-depth24/1");
assert.equal(witness.issuerKeyId, credential.issuerKeyId);
assert.equal(witness.statusId, credential.statusId);
assert.deepEqual(witness.chunkLimbsLittleEndian, record(reference.packedStatus, "packed status").chunkLimbsLittleEndian);
assert.deepEqual(witness.siblingsBottomUp, record(reference.packedStatus, "packed status").siblingsBottomUp);
assert.equal((witness.siblingsBottomUp as unknown[]).length, 24, "depth-24 witness must carry 24 siblings");
assert.equal("directionsBottomUp" in witness, false, "directions must be derived from the private status id");

const snapshot = record(witness.snapshot, "status snapshot reference");
exactKeys(
  snapshot,
  ["chainId", "issuanceRegistry", "snapshotId", "root", "activatedThroughStatusId", "publishedAt"],
  "status snapshot reference",
);
assert.equal(snapshot.chainId, transcript.authorization.chainId);
assert.equal(snapshot.issuanceRegistry, transcript.authorization.issuanceRegistry.toLowerCase());
assert.equal(snapshot.root, fieldHex(record(reference.packedStatus, "packed status").root));
assert.equal(snapshot.root, transcript.statusSnapshot?.root);
assert.equal(snapshot.snapshotId, transcript.statusSnapshot?.snapshotId);
assert.equal(snapshot.activatedThroughStatusId, transcript.statusSnapshot?.activatedThroughStatusId);
assert.equal(snapshot.publishedAt, transcript.statusSnapshot?.publishedAt);
assert.equal(snapshot.publishedAt, (reference.publicSignals as string[])[17]);
assert(BigInt(String(snapshot.publishedAt)) > 0n && BigInt(String(snapshot.publishedAt)) <= 0xffff_ffffn);

const [chunkLow, chunkHigh] = witness.chunkLimbsLittleEndian as [string, string];
assert(BigInt(chunkLow) < 1n << 128n && BigInt(chunkHigh) < 1n << 128n);
const chunk = BigInt(chunkLow) | (BigInt(chunkHigh) << 128n);
const statusId = BigInt(Number(witness.statusId));
assert.equal((chunk >> (statusId & 0xffn)) & 1n, 0n, "fixture status bit must be allocated and active");
assert.equal(statusId >> 8n, 0n, "fixture directions are all derived as left without storing them");

const payloadKeys = collectKeys(payload);
const forbiddenPayloadKeys = [
  "issuerSecretScalar",
  "nonceScalar",
  "nonceCounter",
  "auxiliaryRandomness",
  "challengeField",
  "challengeScalar",
  "directionsBottomUp",
  "duplicateKey",
  "rawNullifier",
] as const;
assert.deepEqual(contract.forbiddenPayloadKeys, forbiddenPayloadKeys);
for (const forbidden of forbiddenPayloadKeys) {
  assert.equal(payloadKeys.has(forbidden), false, `production payload must omit ${forbidden}`);
}
assert.equal(
  JSON.stringify(payload).includes(String(referenceIssuer.auxiliaryRandomness)),
  false,
  "issuer CSPRNG auxiliary randomness must never enter the vault",
);

const manifestNames = (signalManifest.signals as Array<{ name: string }>).map(({ name }) => name);
const interfaceNames = record(record(frozenInterface.publicSignals, "interface signals"), "interface signals").names;
assert.deepEqual(contract.frozenPublicSignalNames, manifestNames);
assert.deepEqual(contract.frozenPublicSignalNames, interfaceNames);
assert.equal((contract.frozenPublicSignalNames as string[]).length, 18);

const refresh = record(contract.refreshPrivacyContract, "refresh privacy contract");
assert.equal(refresh.schema, "org.proofofhumanity.zk-holder-private-status-refresh/1");
assert.equal(refresh.version, 1);
assert.deepEqual(refresh.requestFields, [
  "schema",
  "version",
  "jobId",
  "priorVaultSha256",
  "vault",
  "unlock",
  "cohortBundles",
]);
assert.deepEqual(refresh.cohortBundleFields, ["resolution", "snapshotBytes", "attestationBytes"]);
assert.deepEqual(refresh.resolutionFields, [
  "chainId",
  "issuanceRegistry",
  "registryRuntimeCodehash",
  "issuerKeyId",
  "issuerActive",
  "snapshotId",
  "snapshotHash",
  "snapshotContentSha256",
  "attestationSetSha256",
  "root",
  "activatedThroughStatusId",
  "publishedAt",
  "revoked",
  "accepted",
  "observationBlockNumber",
  "observationBlockHash",
  "observationBlockTimestamp",
  "validUntil",
  "finalityRuleId",
  "resolverConfigHash",
  "reconcilerConfigHash",
]);
assert.equal(refresh.networkAfterDecrypt, false);
assert.equal(refresh.progressAfterDecrypt, false);
const publicSelectors = new Set(refresh.publicDownloadSelectors as string[]);
for (const selector of refresh.forbiddenRemoteSelectors as string[]) {
  assert.equal(publicSelectors.has(selector), false, `remote refresh must not select by ${selector}`);
}
assert.equal(publicSelectors.has("latestAcceptedSnapshot"), false);
assert.deepEqual(refresh.cas, {
  input: "priorVaultSha256",
  hash: "sha256-rfc8785-entire-portable-credential-vault",
  returned: false,
  commit: "atomic-old-or-complete-new",
});
const resourceLimits = record(refresh.resourceLimits, "refresh resource limits");
assert.equal(resourceLimits.cohortBundles, 32);
assert.equal(resourceLimits.totalSnapshotBytes, 64 * 1024 * 1024);
assert.equal(resourceLimits.totalSnapshotChunks, 1_000_000);
assert.equal(resourceLimits.totalAttestationBytes, 128 * 1024);
assert.equal(resourceLimits.workerMemoryBytes, 256 * 1024 * 1024);
assert.equal(resourceLimits.jobMilliseconds, 60_000);
const resultContract = record(refresh.result, "refresh result contract");
assert.equal(resultContract.schema, "org.proofofhumanity.zk-holder-private-status-refresh-result/1");
assert.deepEqual(resultContract.updatedFields, ["replacementVault"]);
assert.deepEqual(resultContract.unchangedFields, []);
assert.deepEqual(resultContract.failedFields, ["code"]);
assert.deepEqual(resultContract.failureCodes, [
  "INVALID_REQUEST",
  "PROFILE_REJECTED",
  "VAULT_REJECTED",
  "SNAPSHOT_REJECTED",
  "CREDENTIAL_UNUSABLE",
  "RESOURCE_LIMIT",
  "CANCELLED",
  "DEADLINE_EXCEEDED",
  "INTERNAL_ERROR",
]);

const trustBundle = record(refresh.trustBundle, "refresh trust bundle");
assert.equal(trustBundle.schema, "org.proofofhumanity.zk-holder-status-refresh-trust-bundle/1");
assert.deepEqual(trustBundle.attestationFields, ["signer", "signature"]);
assert.deepEqual((trustBundle.resolverEip712Domain as Record<string, unknown>).fields, [
  "chainId",
  "verifyingContract",
]);
assert.equal((trustBundle.resolverPrimaryType as string[]).at(-3), "uint64 observationBlockTimestamp");
assert.equal((trustBundle.resolverPrimaryType as string[]).at(-2), "uint64 validUntil");

const migrations = contract.migrationCases as Array<{
  change: string;
  reissue: boolean;
  authorizedNow?: boolean;
}>;
assert.equal(migrations.find(({ change }) => change === "same-profile-status-root")?.reissue, false);
assert.equal(migrations.find(({ change }) => change === "same-profile-status-root")?.authorizedNow, true);
assert.equal(migrations.find(({ change }) => change === "preallocation-slot-epoch-race")?.authorizedNow, true);
assert.equal(migrations.find(({ change }) => change === "reference-or-unknown-payload")?.reissue, true);
assert.equal(
  migrations.find(({ change }) => change === "allocated-issuer-key-rotation")?.reissue,
  true,
);
assert.equal(
  migrations.find(({ change }) => change === "allocated-issuer-key-rotation")?.authorizedNow,
  false,
  "allocated reissuance is blocked until registry supersession preserves nullifier continuity",
);
for (const migration of migrations.filter(({ change }) => change.startsWith("allocated-"))) {
  assert.equal(migration.authorizedNow, false, `${migration.change} must remain blocked`);
}

console.log("v2 production vault + private status refresh contract: PASS");
