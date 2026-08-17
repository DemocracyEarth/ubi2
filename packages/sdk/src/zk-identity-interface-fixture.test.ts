import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import type { Address, Hex } from "viem";
import {
  decodeZkIdentityPublicSignals,
  encodeZkIdentityPublicSignals,
  zkIssuanceDomainHash,
  zkNullifierScopeHash,
  zkPrivateCredentialFingerprint,
  zkScopedNullifierPreimage,
  type ZkIdentityPublicSignalValues,
} from "./zk-identity-encoding";

interface InterfaceFixture {
  schema: string;
  interfaceVersion: number;
  classification: {
    evmWireContract: string;
    packedStatusProfile: string;
    productionCryptography: string;
  };
  privateCredential: {
    issuerKeyId: Hex;
    statusId: Hex;
    holderSecret: string;
    credentialBlinding: string;
    dateOfBirth: string;
    nationality: string;
    issuingState: string;
    expiryDate: string;
    documentClass: "epassport";
    assurance: "chip-auth";
    issuedAtEpoch: number;
    diagnosticFingerprint: Hex;
  };
  issuanceDomain: { chainId: number; registry: Address; hash: Hex };
  nullifierScope: {
    mode: "single-use";
    chainId: number;
    verifier: Address;
    consumer: Address;
    context: Hex;
    policyHash: Hex;
    hash: Hex;
    preimage: string[];
  };
  publicSignals: {
    names: string[];
    semanticValues: {
      circuitId: Hex;
      issuerKeyId: Hex;
      activeRoot: Hex;
      policyHash: Hex;
      presentationBindingHash: Hex;
      nullifierScopeHash: Hex;
      scopedNullifier: string;
      subject: Address;
      result: boolean;
      credentialEpoch: number;
      statusEpoch: number;
    };
    values: string[];
  };
  packedStatusTestnetProfile: {
    statusIdBits: number;
    chunkBits: number;
    treeDepth: number;
    slotZero: string;
    activeBit: number;
    unallocatedOrRevokedBit: number;
    hashSuite: string;
  };
  negativeMutations: Array<{
    name: string;
    index: number;
    value: string;
    alsoIndex?: number;
    alsoValue?: string;
  }>;
  productionBlockers: string[];
}

const fixture = JSON.parse(
  await readFile(
    new URL("../../../fixtures/v2-identity/interface-v1.json", import.meta.url),
    "utf8",
  ),
) as InterfaceFixture;

assert.equal(fixture.schema, "org.proofofhumanity.v2-cross-lane-interface/1");
assert.equal(fixture.interfaceVersion, 1);
assert.deepEqual(fixture.classification, {
  evmWireContract: "frozen",
  packedStatusProfile: "testnet-integration-only",
  productionCryptography: "unratified",
});
assert.ok(
  fixture.productionBlockers.includes("circuit-native credential commitment and hash parameters"),
  "the fixture must not imply that research credential cryptography is production-ready",
);

const credential = {
  ...fixture.privateCredential,
  holderSecret: BigInt(fixture.privateCredential.holderSecret),
  credentialBlinding: BigInt(fixture.privateCredential.credentialBlinding),
};
assert.equal(
  zkPrivateCredentialFingerprint(credential),
  fixture.privateCredential.diagnosticFingerprint,
  "private credential field order drifted",
);
assert.equal(
  zkIssuanceDomainHash(fixture.issuanceDomain),
  fixture.issuanceDomain.hash,
  "issuance chain/registry domain drifted",
);

const scope = {
  mode: fixture.nullifierScope.mode,
  chainId: fixture.nullifierScope.chainId,
  verifier: fixture.nullifierScope.verifier,
  consumer: fixture.nullifierScope.consumer,
  context: fixture.nullifierScope.context,
  policyHash: fixture.nullifierScope.policyHash,
};
assert.equal(zkNullifierScopeHash(scope), fixture.nullifierScope.hash, "nullifier scope drifted");
assert.deepEqual(
  zkScopedNullifierPreimage(credential.holderSecret, scope).map(String),
  fixture.nullifierScope.preimage,
  "nullifier circuit preimage drifted",
);

const semanticValues: ZkIdentityPublicSignalValues = {
  ...fixture.publicSignals.semanticValues,
  scopedNullifier: BigInt(fixture.publicSignals.semanticValues.scopedNullifier),
};
const signals = encodeZkIdentityPublicSignals(semanticValues);
assert.deepEqual(signals.map(String), fixture.publicSignals.values, "18-signal layout drifted");
assert.deepEqual(decodeZkIdentityPublicSignals(signals), semanticValues);
assert.equal(fixture.publicSignals.names.length, 18);

const expectedFailures: Record<string, RegExp> = {
  "unsupported-layout": /unsupported ZK identity public-signal layout/u,
  "zero-policy-hash": /policy hash must not be zero/u,
  "noncanonical-nullifier": /canonical BN254/u,
  "zero-subject": /subject must not be the zero address/u,
  "nonboolean-result": /result must be zero or one/u,
};
for (const mutation of fixture.negativeMutations) {
  const mutated = [...signals];
  mutated[mutation.index] = BigInt(mutation.value);
  if (mutation.alsoIndex !== undefined && mutation.alsoValue !== undefined) {
    mutated[mutation.alsoIndex] = BigInt(mutation.alsoValue);
  }
  assert.throws(
    () => decodeZkIdentityPublicSignals(mutated),
    expectedFailures[mutation.name],
    `mutation ${mutation.name} must fail closed`,
  );
}

assert.deepEqual(fixture.packedStatusTestnetProfile, {
  statusIdBits: 32,
  chunkBits: 256,
  treeDepth: 24,
  slotZero: "sentinel",
  activeBit: 0,
  unallocatedOrRevokedBit: 1,
  hashSuite: "unratified-research-candidate",
});

console.log("v2 cross-lane interface fixture: TypeScript PASS");
