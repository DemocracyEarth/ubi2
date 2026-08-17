import assert from "node:assert/strict";
import { encodeAbiParameters, keccak256, toHex, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { generatePasskeyPrfSalt } from "./credential-vault";
import {
  buildZkHolderIssuanceTranscript,
  zkHolderCredentialFieldElements,
  ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA,
  ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME,
  ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA,
  type ZkHolderCredentialCommitment,
} from "./zk-holder-credential";
import {
  parseZkHolderReferenceVaultPayload,
  unlockZkHolderReferenceVault,
  ZkHolderReferenceHandoff,
  ZK_HOLDER_REFERENCE_PROFILE_STATUS,
  type ZkHolderReferenceClaims,
  type ZkHolderReferencePrivateCredential,
} from "./zk-holder-reference-handoff";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";
import {
  serializeZkSelfIssuanceAuthorization,
  zkSelfIssuanceTypedData,
  type ZkSelfIssuanceArtifact,
  type ZkSelfIssuanceAuthorization,
} from "./zk-self-issuance";

const authority = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
const chainId = 84_532;
const bridge = "0x1111111111111111111111111111111111111111" as const;
const registry = "0x2222222222222222222222222222222222222222" as const;
const claims: ZkHolderReferenceClaims = {
  issuerKeyId: `0x${"23".repeat(32)}`,
  statusId: 17,
  dateOfBirth: "2000-02-29",
  nationality: " xaa ",
  issuingState: "xab",
  expiryDate: "2035-12-31",
  documentClass: "epassport",
  assurance: "chip-auth",
  issuedAtEpoch: 402,
};

// A deterministic test-only function over the exact field preimage. It exercises
// the handoff trust boundary without pretending to be the production commitment.
function syntheticCommitmentBuilder(privateInputJson: string): string {
  const input = JSON.parse(privateInputJson) as ZkHolderReferencePrivateCredential;
  const fields = zkHolderCredentialFieldElements({
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
  });
  const digest = BigInt(
    keccak256(encodeAbiParameters([{ type: "uint256[]" }], [fields])),
  );
  const commitment = (digest % (BN254_SCALAR_FIELD - 1n)) + 1n;
  return JSON.stringify({
    schema: ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA,
    credentialSchema: ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA,
    commitmentScheme: ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME,
    issuerKeyId: input.issuerKeyId,
    statusId: input.statusId,
    issuedAtEpoch: input.issuedAtEpoch,
    commitment: toHex(commitment, { size: 32 }),
  });
}

async function syntheticTranscript(commitment: ZkHolderCredentialCommitment) {
  const authorization: ZkSelfIssuanceAuthorization = {
    subject: "0x3333333333333333333333333333333333333333",
    duplicateKey: `0x${"44".repeat(32)}`,
    credentialCommitment: BigInt(commitment.commitment),
    issuerKeyId: commitment.issuerKeyId,
    expectedStatusId: commitment.statusId,
    expectedEpoch: commitment.issuedAtEpoch,
    deadline: 1_900_000_000n,
    selfConfigId: `0x${"55".repeat(32)}`,
  };
  const signature = await authority.signTypedData(
    zkSelfIssuanceTypedData({ chainId, bridge, authorization }),
  );
  const artifact: ZkSelfIssuanceArtifact = {
    chainId,
    bridge,
    registry,
    authorization: serializeZkSelfIssuanceAuthorization(authorization),
    signature,
  };
  return buildZkHolderIssuanceTranscript({
    commitment,
    artifact,
    verificationAuthority: authority.address,
    allocation: {
      transactionHash: `0x${"66".repeat(32)}`,
      blockNumber: 15_001n,
      blockHash: `0x${"77".repeat(32)}`,
      logIndex: 3,
      issuerKeyId: commitment.issuerKeyId,
      statusId: commitment.statusId,
      credentialCommitment: BigInt(commitment.commitment),
      issuedAtEpoch: commitment.issuedAtEpoch,
    },
    statusSnapshot: {
      transactionHash: `0x${"88".repeat(32)}`,
      blockNumber: 15_009n,
      blockHash: `0x${"99".repeat(32)}`,
      logIndex: 1,
      snapshotId: 4,
      root: "0x0a113b98ce937446f2736264862473af1f0222ef413291a6869847d432bb0d05",
      activatedThroughStatusId: commitment.statusId,
      publishedAt: 1_900_000_100n,
    },
  });
}

const handoff = new ZkHolderReferenceHandoff({ buildCommitment: syntheticCommitmentBuilder });
const preparation = await handoff.prepare(claims);
assert.equal(preparation.commitment.statusId, claims.statusId);
assert.match(preparation.sessionId, /^[A-Za-z0-9_-]{22}$/u);
const publicPreparation = JSON.stringify(preparation);
for (const forbidden of [
  "dateOfBirth",
  "nationality",
  "holderSecret",
  "credentialBlinding",
  claims.dateOfBirth,
  claims.expiryDate,
]) {
  assert(!publicPreparation.includes(forbidden), `sanitized preparation must omit ${forbidden}`);
}
await assert.rejects(handoff.prepare(claims), /already has a pending/u);

const transcript = await syntheticTranscript(preparation.commitment);
const credentialId = "c3ludGhldGljLWhvbGRlci1wYXNza2V5";
const prfOutput = crypto.getRandomValues(new Uint8Array(32));
const vault = await handoff.sealReferenceVault({
  sessionId: preparation.sessionId,
  issuanceTranscript: transcript,
  rpId: "proofofhumanity.org",
  enrollment: { credentialId, prfSalt: generatePasskeyPrfSalt(), prfOutput },
});
assert.equal(vault.binding.schema, "org.proofofhumanity.zk-holder-reference-vault-payload/1");
const serializedVault = JSON.stringify(vault);
for (const forbidden of [
  "dateOfBirth",
  "nationality",
  "holderSecret",
  "credentialBlinding",
  claims.dateOfBirth,
  claims.expiryDate,
]) {
  assert(!serializedVault.includes(forbidden), `encrypted vault metadata must omit ${forbidden}`);
}

const payload = await unlockZkHolderReferenceVault(vault, { credentialId, prfOutput });
assert.equal(payload.profileStatus, ZK_HOLDER_REFERENCE_PROFILE_STATUS);
assert.equal(payload.presentationReady, false);
assert.equal(payload.credential.nationality, "XAA");
assert.equal(payload.credential.issuingState, "XAB");
assert.equal(payload.issuanceTranscript.state, "snapshot-covered");
assert.deepEqual(payload.commitment, preparation.commitment);
const holderSecret = BigInt(payload.credential.holderSecret);
const credentialBlinding = BigInt(payload.credential.credentialBlinding);
assert(holderSecret > 0n && holderSecret < BN254_SCALAR_FIELD);
assert(credentialBlinding > 0n && credentialBlinding < BN254_SCALAR_FIELD);
assert.notEqual(holderSecret, credentialBlinding);
await assert.rejects(
  handoff.sealReferenceVault({
    sessionId: preparation.sessionId,
    issuanceTranscript: transcript,
    rpId: "proofofhumanity.org",
    enrollment: { credentialId, prfSalt: generatePasskeyPrfSalt(), prfOutput },
  }),
  /missing or expired/u,
  "a sealed session cannot be replayed",
);
await assert.rejects(
  unlockZkHolderReferenceVault(vault, {
    credentialId,
    prfOutput: crypto.getRandomValues(new Uint8Array(32)),
  }),
  /could not unlock/u,
);

assert.throws(
  () => parseZkHolderReferenceVaultPayload({ ...payload, presentationReady: true }),
  /presentation-enabled/u,
  "a reference payload can never opt itself into presentation readiness",
);
assert.throws(
  () =>
    parseZkHolderReferenceVaultPayload({
      ...payload,
      credential: { ...payload.credential, holderSecret: `0${payload.credential.holderSecret}` },
    }),
  /canonical nonzero decimal/u,
);
const tamperedTranscript = JSON.parse(JSON.stringify(payload.issuanceTranscript)) as Record<string, unknown>;
(tamperedTranscript.allocation as Record<string, unknown>).logIndex = 4;
assert.throws(
  () => parseZkHolderReferenceVaultPayload({ ...payload, issuanceTranscript: tamperedTranscript }),
  /hash mismatch/u,
);

// A transcript for a different commitment fails closed and consumes the local session.
const mismatchHandoff = new ZkHolderReferenceHandoff({ buildCommitment: syntheticCommitmentBuilder });
const mismatchPreparation = await mismatchHandoff.prepare({ ...claims, statusId: 18 });
await assert.rejects(
  mismatchHandoff.sealReferenceVault({
    sessionId: mismatchPreparation.sessionId,
    issuanceTranscript: transcript,
    rpId: "proofofhumanity.org",
    enrollment: { credentialId, prfSalt: generatePasskeyPrfSalt(), prfOutput },
  }),
  /does not match/u,
);
assert.equal(mismatchHandoff.abort(mismatchPreparation.sessionId), false);

// Expiration and explicit teardown remove all retained references.
const expiringHandoff = new ZkHolderReferenceHandoff({
  buildCommitment: syntheticCommitmentBuilder,
  sessionTtlMs: 1_000,
});
const expiringPreparation = await expiringHandoff.prepare({ ...claims, statusId: 19 });
await new Promise((resolve) => setTimeout(resolve, 1_050));
assert.equal(expiringHandoff.abort(expiringPreparation.sessionId), false);
const destroyedPreparation = await expiringHandoff.prepare({ ...claims, statusId: 20 });
expiringHandoff.destroy();
assert.equal(expiringHandoff.abort(destroyedPreparation.sessionId), false);

// Builder failures and malformed outputs cannot echo private claims through this API.
const leakingBuilder = new ZkHolderReferenceHandoff({
  buildCommitment: () => {
    throw new Error(`private value: ${claims.dateOfBirth}`);
  },
});
await assert.rejects(
  leakingBuilder.prepare(claims),
  (error: unknown) =>
    error instanceof Error &&
    error.message === "circuit-native holder commitment failed" &&
    !error.message.includes(claims.dateOfBirth),
);
const extraFieldBuilder = new ZkHolderReferenceHandoff({
  buildCommitment: (source) => ({ ...JSON.parse(syntheticCommitmentBuilder(source)), privateClaim: "XAA" }),
});
await assert.rejects(
  extraFieldBuilder.prepare(claims),
  /returned an invalid descriptor/u,
);
const mismatchedDescriptorBuilder = new ZkHolderReferenceHandoff({
  buildCommitment: (source) => {
    const descriptor = JSON.parse(syntheticCommitmentBuilder(source)) as ZkHolderCredentialCommitment;
    return { ...descriptor, statusId: descriptor.statusId + 1 };
  },
});
await assert.rejects(
  mismatchedDescriptorBuilder.prepare(claims),
  /does not match the private input/u,
);
const unknownClaimHandoff = new ZkHolderReferenceHandoff({ buildCommitment: syntheticCommitmentBuilder });
await assert.rejects(
  unknownClaimHandoff.prepare({ ...claims, passportNumber: "SYNTHETIC-NOT-ALLOWED" } as ZkHolderReferenceClaims),
  /unknown fields/u,
);
const liveCountryHandoff = new ZkHolderReferenceHandoff({ buildCommitment: syntheticCommitmentBuilder });
await assert.rejects(
  liveCountryHandoff.prepare({ ...claims, nationality: "AAA" }),
  /only XAA-XZZ synthetic country codes/u,
  "the reference path cannot persist a real-country credential",
);

let finishBuilder: (() => void) | undefined;
const inFlightHandoff = new ZkHolderReferenceHandoff({
  buildCommitment: (source) =>
    new Promise((resolve) => {
      finishBuilder = () => resolve(syntheticCommitmentBuilder(source));
    }),
});
const inFlightPreparation = inFlightHandoff.prepare(claims);
await assert.rejects(inFlightHandoff.prepare(claims), /already has a pending/u);
inFlightHandoff.destroy();
if (!finishBuilder) throw new Error("synthetic deferred commitment builder did not start");
finishBuilder();
await assert.rejects(inFlightPreparation, /destroyed during preparation/u);

console.log("zk holder reference handoff: CSPRNG + one-shot transcript-bound encrypted vault PASS");
