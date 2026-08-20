import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createPasskeyProtectedCredentialVault, generatePasskeyPrfSalt } from "./credential-vault";
import { ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS } from "./zk-holder-profile-browser-runtime";
import {
  parseZkHolderProfileProverCommand,
  parseZkHolderProfileProvingReceipt,
  serializeZkHolderGroth16Proof,
  serveZkHolderProfileProverWorker,
  ZkHolderProfileProverClient,
  ZkHolderProfileProverError,
  ZK_HOLDER_PROFILE_ID,
  ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID,
  ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID,
  ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256,
  type ZkHolderProfileProvingEngine,
  type ZkHolderProfileProvingRequest,
  type ZkHolderProfileWorkerLike,
  type ZkHolderProfileWorkerScopeLike,
} from "./zk-holder-profile-prover-worker";

const wasmBytes = new Uint8Array(await readFile(new URL("../../../fixtures/v2-production-crypto/holder-profile-synthetic-v1.wasm", import.meta.url)));
const credentialId = "c3ludGhldGljLXByb2ZpbGUtcGFzc2tleQ";
const prfOutput = new Uint8Array(32).fill(0x31);
const privateMarker = "synthetic-worker-private-XAA-credential";
const vault = await createPasskeyProtectedCredentialVault(
  { schema: "synthetic-test-vault/1", privateMarker },
  { schema: "synthetic-test-vault/1", rpId: "proofofhumanity.org" },
  { credentialId, prfSalt: generatePasskeyPrfSalt(), prfOutput },
);
const proof = serializeZkHolderGroth16Proof([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]);

function request(overrides: Partial<ZkHolderProfileProvingRequest> = {}): ZkHolderProfileProvingRequest {
  return {
    profile: { mode: "synthetic", profileId: ZK_HOLDER_PROFILE_ID, fixtureId: ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID },
    artifacts: [{ role: "wasmModule", sha256: ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256, bytes: wasmBytes }],
    vault,
    unlock: { credentialId, prfOutput },
    expectedPublicSignals: ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS,
    ...overrides,
  };
}

interface Harness {
  worker: ZkHolderProfileWorkerLike;
  hostEnvelope: unknown;
  workerMessages: unknown[];
  terminated(): boolean;
}

function harness(engine: ZkHolderProfileProvingEngine): Harness {
  let stopped = false;
  let hostEnvelope: unknown;
  const workerMessages: unknown[] = [];
  const worker: ZkHolderProfileWorkerLike = {
    onmessage: null,
    onerror: null,
    postMessage(message, transfer = []) {
      const delivered = structuredClone(message, { transfer: [...transfer] });
      if ((delivered as { kind?: string }).kind === "start") {
        const command = delivered as { vault: unknown; profile: unknown; artifacts: Array<{ role: string; sha256: string; bytes: Uint8Array }> };
        hostEnvelope = {
          vault: structuredClone(command.vault),
          profile: structuredClone(command.profile),
          artifacts: command.artifacts.map(({ role, sha256, bytes }) => ({ role, sha256, bytes: bytes.byteLength })),
        };
      }
      queueMicrotask(() => { if (!stopped) scope.onmessage?.({ data: delivered }); });
    },
    terminate() { stopped = true; },
  };
  const scope: ZkHolderProfileWorkerScopeLike = {
    onmessage: null,
    postMessage(message) {
      workerMessages.push(structuredClone(message));
      queueMicrotask(() => { if (!stopped) worker.onmessage?.({ data: structuredClone(message) }); });
    },
  };
  serveZkHolderProfileProverWorker(scope, engine);
  return { worker, get hostEnvelope() { return hostEnvelope; }, workerMessages, terminated: () => stopped };
}

function engine(overrides?: { locallyVerified?: boolean; signals?: readonly bigint[]; onProve?: () => void; onDestroy?: () => void }): ZkHolderProfileProvingEngine {
  return {
    admitsProductionProfile: () => false,
    acceptsVaultBinding: (mode, schema) => mode === "synthetic" && schema === "synthetic-test-vault/1",
    parseVaultPayload(mode, value) {
      assert.equal(mode, "synthetic");
      assert.deepEqual(value, { schema: "synthetic-test-vault/1", privateMarker });
      return value;
    },
    async prove(input) {
      overrides?.onProve?.();
      assert.equal(input.context.circuitId, ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID);
      assert.equal(input.context.manifest, null);
      assert.equal(input.artifacts.get("wasmModule")?.byteLength, wasmBytes.byteLength);
      input.reportProgress({ phase: "proving", percent: 65, memoryBytes: 48 * 1024 * 1024 });
      input.reportProgress({ phase: "verifying", percent: 95, memoryBytes: 52 * 1024 * 1024 });
      return {
        proof,
        publicSignals: overrides?.signals ?? ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS,
        locallyVerified: overrides?.locallyVerified ?? true,
        retainedMemoryBytes: 53 * 1024 * 1024,
      };
    },
    destroy: overrides?.onDestroy,
  };
}

function expectCode(code: ZkHolderProfileProverError["code"]) {
  return (error: unknown) => error instanceof ZkHolderProfileProverError && error.code === code;
}

let proved = false;
let destroyed = false;
const complete = harness(engine({ onProve: () => (proved = true), onDestroy: () => (destroyed = true) }));
const receipt = await new ZkHolderProfileProverClient(() => complete.worker).prove(request());
assert(proved && destroyed && complete.terminated());
assert.equal(receipt.mode, "synthetic");
assert.equal(receipt.presentationReady, false);
assert.equal(receipt.manifestHash, null);
assert.equal(receipt.circuitId, ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID);
assert.equal(receipt.proof, proof);
assert.equal(receipt.proof.length, 2 + 256 * 2);
assert.equal(receipt.publicSignals.length, 2 + 18 * 32 * 2);
assert.equal(receipt.locallyVerified, true);
assert.deepEqual(receipt.artifactDigests, [{ role: "wasmModule", sha256: ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256 }]);
assert.deepEqual(parseZkHolderProfileProvingReceipt(receipt), receipt);
assert(!JSON.stringify({ host: complete.hostEnvelope, events: complete.workerMessages, receipt }).includes(privateMarker));
assert.equal(prfOutput.every((byte) => byte === 0x31), true, "the caller-owned PRF result is not mutated");
assert.equal(wasmBytes[0], 0, "the caller-owned public artifact is not zeroized");

// A single changed artifact byte fails before vault decryption or proving.
const changedWasm = new Uint8Array(wasmBytes);
changedWasm[changedWasm.length - 1] ^= 1;
let hashMismatchProved = false;
const hashMismatch = harness(engine({ onProve: () => (hashMismatchProved = true) }));
await assert.rejects(
  new ZkHolderProfileProverClient(() => hashMismatch.worker).prove(request({
    artifacts: [{ role: "wasmModule", sha256: ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256, bytes: changedWasm }],
  })),
  expectCode("artifact-hash-mismatch"),
);
assert.equal(hashMismatchProved, false);

// Production-shaped requests cannot use an unapproved or malformed manifest.
let candidateProved = false;
const candidate = harness(engine({ onProve: () => (candidateProved = true) }));
await assert.rejects(
  new ZkHolderProfileProverClient(() => candidate.worker).prove(request({
    profile: {
      mode: "production",
      profileId: ZK_HOLDER_PROFILE_ID,
      manifest: { releaseStatus: "candidate" },
      admission: {},
    },
  })),
  expectCode("profile-not-admitted"),
);
assert.equal(candidateProved, false);

const badUnlock = harness(engine());
await assert.rejects(
  new ZkHolderProfileProverClient(() => badUnlock.worker).prove(request({
    unlock: { credentialId, prfOutput: new Uint8Array(32).fill(0x99) },
  })),
  expectCode("vault-unlock-failed"),
);

const falseVerification = harness(engine({ locallyVerified: false }));
await assert.rejects(
  new ZkHolderProfileProverClient(() => falseVerification.worker).prove(request()),
  expectCode("proof-verification-failed"),
);

const changedSignals = [...ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS];
changedSignals[13] += 1n;
const signalMismatch = harness(engine({ signals: changedSignals }));
await assert.rejects(
  new ZkHolderProfileProverClient(() => signalMismatch.worker).prove(request()),
  expectCode("proof-verification-failed"),
);

assert.throws(
  () => parseZkHolderProfileProvingReceipt({ ...receipt, presentationReady: true }),
  /relabeled/u,
);
assert.throws(
  () => parseZkHolderProfileProvingReceipt({ ...receipt, publicSignals: `${receipt.publicSignals}00` }),
  /must be 576 bytes/u,
);
assert.throws(
  () => parseZkHolderProfileProverCommand({ schema: "wrong", version: 1, kind: "cancel", jobId: "00".repeat(16) }),
  /unsupported/u,
);

console.log("zk holder profile prover worker: admission + artifacts + private vault + proof PASS");
