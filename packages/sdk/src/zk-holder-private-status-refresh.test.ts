import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { toHex, type Address, type Hex } from "viem";
import {
  addPasskeyKeySlot,
  createPasskeyProtectedCredentialVault,
  generatePasskeyPrfSalt,
  unlockCredentialVault,
  type PortableCredentialVault,
} from "./credential-vault";
import {
  serializeZkIdentityPackedStatusSnapshot,
  zkIdentityPackedStatusAttestationTypedData,
  zkIdentityPackedStatusSnapshotHash,
  type ZkIdentityPackedStatusSnapshot,
} from "./zk-identity-status-snapshot";
import {
  commitZkHolderPrivateStatusRefresh,
  createZkHolderPrivateStatusRefreshRequest,
  parseZkHolderPrivateStatusRefreshResult,
  serializeZkHolderStatusRefreshTrustBundle,
  serveZkHolderPrivateStatusRefreshWorker,
  zkHolderCredentialVaultSha256,
  zkHolderStatusResolutionTypedData,
  ZkHolderPrivateStatusRefreshClient,
  ZkHolderPrivateStatusRefreshDisabledEngine,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATION_BYTES,
  type ZkHolderPrivateStatusAtomicVaultStore,
  type ZkHolderPrivateStatusRefreshEngine,
  type ZkHolderPrivateStatusRefreshPolicy,
  type ZkHolderPrivateStatusRefreshRequest,
  type ZkHolderPrivateStatusRefreshWorkerLike,
  type ZkHolderPrivateStatusRefreshWorkerScopeLike,
  type ZkHolderStatusRefreshCohortBundle,
  type ZkHolderStatusRefreshCohortPolicy,
  type ZkHolderStatusResolution,
} from "./zk-holder-private-status-refresh";
import {
  parseZkHolderProductionVaultPayload,
  ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA,
} from "./zk-holder-production-vault";
import { ZK_HOLDER_PROFILE_ID } from "./zk-holder-profile-prover-worker";

const contract = JSON.parse(
  await readFile(
    new URL("../../../fixtures/v2-identity/production-vault-status-v1.json", import.meta.url),
    "utf8",
  ),
) as { payload: Record<string, unknown> };
const payload = parseZkHolderProductionVaultPayload(contract.payload);
const privateMarker = payload.credential.holderSecret;

assert.equal(payload.profile.profileId, ZK_HOLDER_PROFILE_ID);
assert.equal(payload.profile.parameterManifestSha256, ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256);
assert.throws(
  () => parseZkHolderProductionVaultPayload({ ...contract.payload, privateSelector: payload.credential.statusId }),
  /missing or unknown fields/u,
);
assert.throws(
  () => parseZkHolderProductionVaultPayload({
    ...contract.payload,
    profile: { ...payload.profile, parameterManifestSha256: "00".repeat(32) },
  }),
  /ratified profile/u,
);
assert.throws(
  () => parseZkHolderProductionVaultPayload({
    ...contract.payload,
    issuerAuthentication: { ...payload.issuerAuthentication, responseScalar: "01" },
  }),
  /canonical decimal/u,
);
assert.throws(
  () => parseZkHolderProductionVaultPayload({
    ...contract.payload,
    statusWitness: {
      ...payload.statusWitness,
      chunkLimbsLittleEndian: [
        (BigInt(payload.statusWitness.chunkLimbsLittleEndian[0]) | (1n << 7n)).toString(),
        payload.statusWitness.chunkLimbsLittleEndian[1],
      ],
    },
  }),
  /not active/u,
);

const credentialId = "cHJvZHVjdGlvbi12YXVsdC1wYXNza2V5";
const unlockSecret = new Uint8Array(32).fill(0x41);
const vault = await createPasskeyProtectedCredentialVault(
  payload,
  { schema: ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA, rpId: "proofofhumanity.org" },
  { credentialId, prfSalt: generatePasskeyPrfSalt(), prfOutput: unlockSecret },
);

const snapshotAccounts = [
  privateKeyToAccount(`0x${"11".repeat(32)}`),
  privateKeyToAccount(`0x${"22".repeat(32)}`),
] as const;
const resolverAccounts = [
  privateKeyToAccount(`0x${"33".repeat(32)}`),
  privateKeyToAccount(`0x${"44".repeat(32)}`),
] as const;
const NOW_SECONDS = 1_788_480_100;
const firstCohort = cohort({
  chainId: payload.statusWitness.snapshot.chainId,
  issuanceRegistry: payload.statusWitness.snapshot.issuanceRegistry,
  issuerKeyId: payload.statusWitness.issuerKeyId,
  seed: "55",
});
const secondCohort = cohort({
  chainId: "84533",
  issuanceRegistry: "0x4444444444444444444444444444444444444444",
  issuerKeyId: `0x${"66".repeat(32)}`,
  seed: "77",
});
const policy: ZkHolderPrivateStatusRefreshPolicy = {
  profileId: ZK_HOLDER_PROFILE_ID,
  parameterManifestSha256: ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  productionApproved: true,
  cohorts: [firstCohort, secondCohort],
};

function cohort(input: {
  chainId: string;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  seed: string;
}): ZkHolderStatusRefreshCohortPolicy {
  return {
    chainId: input.chainId,
    issuanceRegistry: input.issuanceRegistry,
    registryRuntimeCodehash: `0x${input.seed.repeat(32)}`,
    issuerKeyId: input.issuerKeyId,
    finalityRuleId: `0x${"88".repeat(32)}`,
    resolverConfigHash: `0x${"99".repeat(32)}`,
    reconcilerConfigHash: `0x${"aa".repeat(32)}`,
    resolverSigners: resolverAccounts.map(({ address }) => address),
    resolverThreshold: 2,
    reconcilerSigners: snapshotAccounts.map(({ address }) => address),
    reconcilerThreshold: 2,
  };
}

function activeChunk(): Hex {
  const [low, high] = payload.statusWitness.chunkLimbsLittleEndian;
  return toHex(BigInt(low) | (BigInt(high) << 128n), { size: 32 });
}

async function signedBundle(
  configured: ZkHolderStatusRefreshCohortPolicy,
  snapshotId: number,
  root: Hex,
): Promise<ZkHolderStatusRefreshCohortBundle> {
  const snapshot: ZkIdentityPackedStatusSnapshot = {
    schema: "org.proofofhumanity.v2-packed-status-snapshot/1",
    chainId: configured.chainId,
    issuanceRegistry: configured.issuanceRegistry,
    issuerKeyId: configured.issuerKeyId,
    sourceBlockNumber: "100",
    sourceBlockHash: `0x${"bb".repeat(32)}`,
    sourceBlockParentHash: `0x${"cc".repeat(32)}`,
    nextStatusId: 8,
    activatedThroughStatusId: 7,
    root,
    chunks: [{ index: 0, value: activeChunk() }],
  };
  const snapshotText = serializeZkIdentityPackedStatusSnapshot(snapshot);
  const snapshotBytes = bytes(snapshotText);
  let resolution: ZkHolderStatusResolution = {
    chainId: configured.chainId,
    issuanceRegistry: configured.issuanceRegistry,
    registryRuntimeCodehash: configured.registryRuntimeCodehash,
    issuerKeyId: configured.issuerKeyId,
    issuerActive: true,
    snapshotId,
    snapshotHash: zkIdentityPackedStatusSnapshotHash(snapshot),
    snapshotContentSha256: sha256(snapshotText),
    attestationSetSha256: "00".repeat(32),
    root,
    activatedThroughStatusId: 7,
    publishedAt: NOW_SECONDS - 100,
    revoked: false,
    accepted: true,
    observationBlockNumber: "101",
    observationBlockHash: `0x${"dd".repeat(32)}`,
    observationBlockTimestamp: (NOW_SECONDS - 10).toString(),
    validUntil: (NOW_SECONDS + 600).toString(),
    finalityRuleId: configured.finalityRuleId,
    resolverConfigHash: configured.resolverConfigHash,
    reconcilerConfigHash: configured.reconcilerConfigHash,
  };
  const snapshotAttestations = await signAll(snapshotAccounts, zkIdentityPackedStatusAttestationTypedData(snapshot));
  const resolutionAttestations = await signAll(resolverAccounts, zkHolderStatusResolutionTypedData(resolution));
  const trustText = serializeZkHolderStatusRefreshTrustBundle({
    schema: "org.proofofhumanity.zk-holder-status-refresh-trust-bundle/1",
    version: 1,
    snapshotAttestations,
    resolutionAttestations,
  });
  resolution = { ...resolution, attestationSetSha256: sha256(trustText) };
  return { resolution, snapshotBytes, attestationBytes: bytes(trustText) };
}

async function signAll(
  accounts: readonly PrivateKeyAccount[],
  typedData: Parameters<PrivateKeyAccount["signTypedData"]>[0],
) {
  const signatures = await Promise.all(accounts.map(async (account) => ({
    signer: account.address,
    signature: await account.signTypedData(typedData),
  })));
  return signatures.sort((left, right) => left.signer.toLowerCase().localeCompare(right.signer.toLowerCase()));
}

function bytes(value: string): ArrayBuffer {
  return new TextEncoder().encode(value).buffer as ArrayBuffer;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function request(
  bundleTransform: (bundles: ZkHolderStatusRefreshCohortBundle[]) => ZkHolderStatusRefreshCohortBundle[] = (value) => value,
): Promise<ZkHolderPrivateStatusRefreshRequest> {
  return requestWithFirstSnapshot(4, toHex(123_456n, { size: 32 }), bundleTransform);
}

async function requestWithFirstSnapshot(
  snapshotId: number,
  root: Hex,
  bundleTransform: (bundles: ZkHolderStatusRefreshCohortBundle[]) => ZkHolderStatusRefreshCohortBundle[] = (value) => value,
): Promise<ZkHolderPrivateStatusRefreshRequest> {
  const bundles = bundleTransform([
    await signedBundle(firstCohort, snapshotId, root),
    await signedBundle(secondCohort, 2, toHex(654_321n, { size: 32 })),
  ]);
  return createZkHolderPrivateStatusRefreshRequest({
    vault,
    unlock: { credentialId, prfOutput: new Uint8Array(unlockSecret).buffer },
    cohortBundles: bundles,
  });
}

interface Harness {
  worker: ZkHolderPrivateStatusRefreshWorkerLike;
  messages: unknown[];
  terminated(): boolean;
  workerPrf(): Uint8Array | undefined;
}

function harness(
  engine: ZkHolderPrivateStatusRefreshEngine,
  workerPolicy: ZkHolderPrivateStatusRefreshPolicy = policy,
): Harness {
  let stopped = false;
  let workerPrf: Uint8Array | undefined;
  const messages: unknown[] = [];
  const worker: ZkHolderPrivateStatusRefreshWorkerLike = {
    onmessage: null,
    onerror: null,
    postMessage(message, transfer = []) {
      const delivered = structuredClone(message, { transfer: [...transfer] });
      workerPrf = new Uint8Array((delivered as ZkHolderPrivateStatusRefreshRequest).unlock.prfOutput);
      queueMicrotask(() => { if (!stopped) scope.onmessage?.({ data: delivered }); });
    },
    terminate() { stopped = true; },
  };
  const scope: ZkHolderPrivateStatusRefreshWorkerScopeLike = {
    onmessage: null,
    postMessage(message) {
      messages.push(structuredClone(message));
      queueMicrotask(() => { if (!stopped) worker.onmessage?.({ data: structuredClone(message) }); });
    },
  };
  serveZkHolderPrivateStatusRefreshWorker(scope, {
    policy: workerPolicy,
    engine,
    now: () => NOW_SECONDS * 1000,
  });
  return { worker, messages, terminated: () => stopped, workerPrf: () => workerPrf };
}

function engine(overrides: {
  admit?: boolean;
  memoryBytes?: number;
  rejectIssuer?: Hex;
  rejectPayload?: boolean;
  counters?: { snapshots: number; payloads: number; paths: number; networks: number; destroyed: number };
} = {}): ZkHolderPrivateStatusRefreshEngine {
  const counters = overrides.counters ?? { snapshots: 0, payloads: 0, paths: 0, networks: 0, destroyed: 0 };
  return {
    admitsProductionProfile: () => overrides.admit ?? true,
    validateSnapshot(snapshot) {
      counters.snapshots += 1;
      if (snapshot.issuerKeyId === overrides.rejectIssuer) throw new Error("invalid decoy snapshot");
    },
    verifyPayload(value) {
      counters.payloads += 1;
      assert.equal(counters.networks, 1, "the network is locked before vault decryption");
      assert.equal(value.credential.holderSecret, privateMarker);
      if (overrides.rejectPayload) throw new Error(`private failure ${privateMarker}`);
    },
    buildStatusPath() {
      counters.paths += 1;
      return {
        chunkLimbsLittleEndian: payload.statusWitness.chunkLimbsLittleEndian,
        siblingsBottomUp: payload.statusWitness.siblingsBottomUp,
      };
    },
    lockNetwork: () => { counters.networks += 1; },
    memoryBytes: () => overrides.memoryBytes ?? 8 * 1024 * 1024,
    destroy: () => { counters.destroyed += 1; },
  };
}

const counters = { snapshots: 0, payloads: 0, paths: 0, networks: 0, destroyed: 0 };
const successHarness = harness(engine({ counters }));
const successRequest = await request();
const priorDigest = successRequest.priorVaultSha256;
const success = await new ZkHolderPrivateStatusRefreshClient(() => successHarness.worker).refresh(successRequest);
assert.equal(success.status, "updated");
assert.deepEqual(counters, { snapshots: 2, payloads: 1, paths: 1, networks: 1, destroyed: 1 });
assert(successHarness.terminated());
assert.equal(successHarness.messages.length, 1, "refresh emits no progress events");
assert.equal(successRequest.unlock.prfOutput.byteLength, 0, "host PRF buffer is transferred, not cloned");
assert(successRequest.cohortBundles.every(({ snapshotBytes, attestationBytes }) =>
  snapshotBytes.byteLength === 0 && attestationBytes.byteLength === 0
));
assert(successHarness.workerPrf()?.every((byte) => byte === 0), "Worker PRF copy is zeroized");
assert(!JSON.stringify(successHarness.messages).includes(privateMarker));
assert(!JSON.stringify(success).includes(priorDigest), "input-only CAS digest never crosses the result boundary");
assert.deepEqual(parseZkHolderPrivateStatusRefreshResult(success), success);

assert.equal(success.status, "updated");
const replacementPayload = parseZkHolderProductionVaultPayload(
  await unlockCredentialVault(success.replacementVault, { credentialId, prfOutput: unlockSecret }),
);
assert.equal(replacementPayload.statusWitness.snapshot.snapshotId, 4);
assert.equal(replacementPayload.statusWitness.snapshot.root, toHex(123_456n, { size: 32 }));
assert.deepEqual(
  { ...replacementPayload, statusWitness: payload.statusWitness },
  payload,
  "refresh replaces only the status witness semantically",
);
assert.deepEqual(success.replacementVault.keySlots, vault.keySlots);
assert.equal(success.replacementVault.vaultId, vault.vaultId);
assert.notEqual(success.replacementVault.payload.iv, vault.payload.iv, "refresh uses a fresh 96-bit AES-GCM IV");

// Atomic whole-envelope CAS commits once and rejects a concurrent key-slot rewrap.
class AtomicStore implements ZkHolderPrivateStatusAtomicVaultStore {
  constructor(public value: PortableCredentialVault) {}
  async compareAndSwap(expected: string, replacement: PortableCredentialVault): Promise<boolean> {
    if (await zkHolderCredentialVaultSha256(this.value) !== expected) return false;
    this.value = replacement;
    return true;
  }
}
const committedStore = new AtomicStore(vault);
assert.equal(await commitZkHolderPrivateStatusRefresh({ store: committedStore, priorVaultSha256: priorDigest, result: success }), "committed");
assert.deepEqual(committedStore.value, success.replacementVault);

const concurrentVault = await addPasskeyKeySlot(
  vault,
  { credentialId, prfOutput: unlockSecret },
  {
    credentialId: "Y29uY3VycmVudC1yZWNvdmVyeS1wYXNza2V5",
    prfSalt: generatePasskeyPrfSalt(),
    prfOutput: new Uint8Array(32).fill(0x52),
  },
);
const staleStore = new AtomicStore(concurrentVault);
assert.equal(await commitZkHolderPrivateStatusRefresh({ store: staleStore, priorVaultSha256: priorDigest, result: success }), "stale");
assert.deepEqual(staleStore.value, concurrentVault, "a stale refresh cannot overwrite concurrent key-slot state");

// An identical snapshot is idempotent; same-id different data is equivocation.
const unchangedCounters = { snapshots: 0, payloads: 0, paths: 0, networks: 0, destroyed: 0 };
const unchangedHarness = harness(engine({ counters: unchangedCounters }));
const sameSnapshot = await new ZkHolderPrivateStatusRefreshClient(() => unchangedHarness.worker).refresh(
  await requestWithFirstSnapshot(3, payload.statusWitness.snapshot.root),
);
assert.equal(sameSnapshot.status, "unchanged");
assert.equal(unchangedCounters.paths, 0);
assert.equal(await commitZkHolderPrivateStatusRefresh({ store: new AtomicStore(vault), priorVaultSha256: priorDigest, result: sameSnapshot }), "not-updated");

const equivocationHarness = harness(engine());
const equivocation = await new ZkHolderPrivateStatusRefreshClient(() => equivocationHarness.worker).refresh(
  await requestWithFirstSnapshot(3, toHex(999_999n, { size: 32 })),
);
assert.deepEqual(equivocation.status === "failed" && equivocation.code, "CREDENTIAL_UNUSABLE");

// Production vault binding is exactly {schema,rpId}; generic-envelope extensions fail before decrypt.
const extendedBindingVault = {
  ...vault,
  binding: { ...vault.binding, selector: payload.credential.statusId },
};
const bindingRequest = await createZkHolderPrivateStatusRefreshRequest({
  vault: extendedBindingVault,
  unlock: { credentialId, prfOutput: new Uint8Array(unlockSecret).buffer },
  cohortBundles: [
    await signedBundle(firstCohort, 4, toHex(123_456n, { size: 32 })),
    await signedBundle(secondCohort, 2, toHex(654_321n, { size: 32 })),
  ],
});
const bindingCounters = { snapshots: 0, payloads: 0, paths: 0, networks: 0, destroyed: 0 };
const bindingHarness = harness(engine({ counters: bindingCounters }));
const bindingFailure = await new ZkHolderPrivateStatusRefreshClient(() => bindingHarness.worker).refresh(bindingRequest);
assert.deepEqual(bindingFailure.status === "failed" && bindingFailure.code, "VAULT_REJECTED");
assert.equal(bindingCounters.payloads, 0);
assert.equal(bindingCounters.networks, 0);

// The checked-in engine and a locally unapproved policy both fail before public bundle or vault work.
const disabledHarness = harness(new ZkHolderPrivateStatusRefreshDisabledEngine());
const disabled = await new ZkHolderPrivateStatusRefreshClient(() => disabledHarness.worker).refresh(await request());
assert.deepEqual(disabled.status === "failed" && disabled.code, "PROFILE_REJECTED");
const unapprovedCounters = { snapshots: 0, payloads: 0, paths: 0, networks: 0, destroyed: 0 };
const unapprovedHarness = harness(
  engine({ counters: unapprovedCounters }),
  { ...policy, productionApproved: false },
);
const unapproved = await new ZkHolderPrivateStatusRefreshClient(() => unapprovedHarness.worker).refresh(await request());
assert.deepEqual(unapproved.status === "failed" && unapproved.code, "PROFILE_REJECTED");
assert.deepEqual(unapprovedCounters, { snapshots: 0, payloads: 0, paths: 0, networks: 0, destroyed: 1 });

// An invalid non-selected cohort rejects before decryption, preventing a selected-issuer oracle.
const decoyCounters = { snapshots: 0, payloads: 0, paths: 0, networks: 0, destroyed: 0 };
const decoyHarness = harness(engine({ rejectIssuer: secondCohort.issuerKeyId, counters: decoyCounters }));
const decoy = await new ZkHolderPrivateStatusRefreshClient(() => decoyHarness.worker).refresh(await request());
assert.deepEqual(decoy.status === "failed" && decoy.code, "SNAPSHOT_REJECTED");
assert.equal(decoyCounters.payloads, 0);
assert.equal(decoyCounters.paths, 0);

// Aggregate byte and runtime-memory limits fail with one bounded code.
const oversized = await request();
oversized.cohortBundles[0] = {
  ...oversized.cohortBundles[0]!,
  attestationBytes: new ArrayBuffer(ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATION_BYTES + 1),
};
let resourceWorkerCreated = false;
const resource = await new ZkHolderPrivateStatusRefreshClient(() => {
  resourceWorkerCreated = true;
  return harness(engine()).worker;
}).refresh(oversized);
assert.deepEqual(resource.status === "failed" && resource.code, "RESOURCE_LIMIT");
assert.equal(resourceWorkerCreated, false, "the host enforces aggregate resource limits before Worker creation");
const memoryHarness = harness(engine({ memoryBytes: 256 * 1024 * 1024 + 1 }));
const memory = await new ZkHolderPrivateStatusRefreshClient(() => memoryHarness.worker).refresh(await request());
assert.deepEqual(memory.status === "failed" && memory.code, "RESOURCE_LIMIT");

// Decrypted errors collapse to CREDENTIAL_UNUSABLE and never echo private data.
const privateFailureHarness = harness(engine({ rejectPayload: true }));
const privateFailure = await new ZkHolderPrivateStatusRefreshClient(() => privateFailureHarness.worker).refresh(await request());
assert.deepEqual(privateFailure.status === "failed" && privateFailure.code, "CREDENTIAL_UNUSABLE");
assert(!JSON.stringify(privateFailureHarness.messages).includes(privateMarker));
assert.deepEqual(Object.keys(privateFailure).sort(), ["code", "jobId", "schema", "status", "version"]);

// Pre-aborted jobs never create a Worker or transfer the unlock buffer.
const cancelledRequest = await request();
const abort = new AbortController();
abort.abort();
let workerCreated = false;
const cancelled = await new ZkHolderPrivateStatusRefreshClient(() => {
  workerCreated = true;
  return harness(engine()).worker;
}).refresh(cancelledRequest, { signal: abort.signal });
assert.deepEqual(cancelled.status === "failed" && cancelled.code, "CANCELLED");
assert.equal(workerCreated, false);
assert.equal(cancelledRequest.unlock.prfOutput.byteLength, 32);

console.log("zk holder private status refresh: parser + all-cohort privacy + CAS + limits PASS");
