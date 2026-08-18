import assert from "node:assert/strict";
import { encodeZkIdentityPublicSignals } from "./zk-identity-encoding";
import {
  parseZkHolderReferenceProverCommand,
  parseZkHolderReferenceProverEvent,
  parseZkHolderReferenceProvingReceipt,
  serveZkHolderReferenceProverWorker,
  ZkHolderReferenceProverClient,
  ZkHolderReferenceProverError,
  ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES,
  type ZkHolderReferenceProvingEngine,
  type ZkHolderReferenceProvingProgress,
  type ZkHolderReferenceWorkerLike,
  type ZkHolderReferenceWorkerScopeLike,
} from "./zk-holder-reference-prover-worker";
import {
  ZK_HOLDER_REFERENCE_PROFILE_STATUS,
  ZK_HOLDER_REFERENCE_WARNING,
} from "./zk-holder-reference-handoff";

const fixtureId = "synthetic:worker-boundary-v1";
const publicSignals = encodeZkIdentityPublicSignals({
  circuitId: `0x${"11".repeat(32)}`,
  issuerKeyId: `0x${"22".repeat(32)}`,
  activeRoot: `0x${"33".repeat(32)}`,
  policyHash: `0x${"44".repeat(32)}`,
  presentationBindingHash: `0x${"55".repeat(32)}`,
  nullifierScopeHash: `0x${"66".repeat(32)}`,
  scopedNullifier: 424_242n,
  subject: "0x7777777777777777777777777777777777777777",
  result: true,
  credentialEpoch: 42,
  statusEpoch: 0,
});

interface Harness {
  worker: ZkHolderReferenceWorkerLike;
  hostMessages: unknown[];
  workerMessages: unknown[];
  terminated(): boolean;
}

function harness(engine: ZkHolderReferenceProvingEngine): Harness {
  let stopped = false;
  const hostMessages: unknown[] = [];
  const workerMessages: unknown[] = [];
  const worker: ZkHolderReferenceWorkerLike = {
    onmessage: null,
    onerror: null,
    postMessage(message) {
      hostMessages.push(structuredClone(message));
      queueMicrotask(() => {
        if (!stopped) scope.onmessage?.({ data: structuredClone(message) });
      });
    },
    terminate() {
      stopped = true;
    },
  };
  const scope: ZkHolderReferenceWorkerScopeLike = {
    onmessage: null,
    postMessage(message) {
      workerMessages.push(structuredClone(message));
      queueMicrotask(() => {
        if (!stopped) worker.onmessage?.({ data: structuredClone(message) });
      });
    },
  };
  serveZkHolderReferenceProverWorker(scope, engine);
  return { worker, hostMessages, workerMessages, terminated: () => stopped };
}

function successfulEngine(options?: {
  resultSignals?: readonly bigint[];
  progress?: readonly ZkHolderReferenceProvingProgress[];
  retainedMemoryBytes?: number;
  proofVerified?: boolean;
  onDestroy?: () => void;
}): ZkHolderReferenceProvingEngine {
  return {
    async runReference(input) {
      assert.equal(input.fixtureId, fixtureId);
      assert.deepEqual(input.expectedPublicSignals, publicSignals);
      for (
        const progress of
          options?.progress ??
          [
            { phase: "loading-artifacts", percent: 10, memoryBytes: 20_000_000 },
            { phase: "building-witness", percent: 35, memoryBytes: 30_000_000 },
            { phase: "proving", percent: 70, memoryBytes: 40_000_000 },
            { phase: "verifying", percent: 95, memoryBytes: 44_000_000 },
          ]
      ) {
        input.reportProgress(progress);
        await Promise.resolve();
      }
      return {
        publicSignals: options?.resultSignals ?? publicSignals,
        proofVerified: options?.proofVerified ?? true,
        retainedMemoryBytes: options?.retainedMemoryBytes ?? 45_000_000,
      };
    },
    destroy: options?.onDestroy,
  };
}

function expectCode(code: ZkHolderReferenceProverError["code"]) {
  return (error: unknown) => error instanceof ZkHolderReferenceProverError && error.code === code;
}

let destroyed = false;
const completeHarness = harness(successfulEngine({ onDestroy: () => (destroyed = true) }));
const observedProgress: ZkHolderReferenceProvingProgress[] = [];
const receipt = await new ZkHolderReferenceProverClient(() => completeHarness.worker).prove({
  fixtureId,
  expectedPublicSignals: publicSignals,
  onProgress: (progress) => observedProgress.push(progress),
});
assert.equal(receipt.profileStatus, ZK_HOLDER_REFERENCE_PROFILE_STATUS);
assert.equal(receipt.warning, ZK_HOLDER_REFERENCE_WARNING);
assert.equal(receipt.presentationReady, false);
assert.equal(receipt.proofVerified, true);
assert.equal(receipt.fixtureId, fixtureId);
assert.equal(receipt.peakMemoryBytes, 45_000_000);
assert.deepEqual(
  observedProgress.map(({ phase, percent }) => [phase, percent]),
  [
    ["initializing", 0],
    ["loading-artifacts", 10],
    ["building-witness", 35],
    ["proving", 70],
    ["verifying", 95],
  ],
);
assert(completeHarness.terminated(), "a completed dedicated worker must be terminated");
assert(destroyed, "worker-private engine teardown must run");
assert(!Object.hasOwn(receipt, "proof"), "the unratified reference boundary must never return proof bytes");
assert(!Object.hasOwn(receipt, "credential"), "the reference receipt must never return a credential");

const startCommand = parseZkHolderReferenceProverCommand(completeHarness.hostMessages[0]);
assert.equal(startCommand.kind, "start");
assert.equal(startCommand.profileStatus, ZK_HOLDER_REFERENCE_PROFILE_STATUS);
const completeEvent = completeHarness.workerMessages
  .map(parseZkHolderReferenceProverEvent)
  .find((event) => event.kind === "complete");
assert(completeEvent?.kind === "complete");
assert.deepEqual(parseZkHolderReferenceProvingReceipt(completeEvent.receipt), receipt);

const serializedBoundary = JSON.stringify({
  host: completeHarness.hostMessages,
  worker: completeHarness.workerMessages,
  receipt,
});
for (const forbidden of [
  "dateOfBirth",
  "nationality",
  "issuingState",
  "expiryDate",
  "holderSecret",
  "credentialBlinding",
  "proofBytes",
]) {
  assert(!serializedBoundary.includes(forbidden), `worker boundary must omit ${forbidden}`);
}

// A malicious engine error must collapse to a bounded code without reflecting sensitive text.
const secretMarker = "XAA-date-2000-02-29-holder-secret-123456";
const errorHarness = harness({
  runReference() {
    throw new Error(secretMarker);
  },
});
await assert.rejects(
  new ZkHolderReferenceProverClient(() => errorHarness.worker).prove({ fixtureId, expectedPublicSignals: publicSignals }),
  (error: unknown) => {
    assert(expectCode("proving-failed")(error));
    assert(!String(error).includes(secretMarker));
    return true;
  },
);
assert(!JSON.stringify(errorHarness.workerMessages).includes(secretMarker));

// Memory over the caller's cap aborts in the worker and never yields a receipt.
const memoryHarness = harness(
  successfulEngine({
    progress: [
      {
        phase: "loading-artifacts",
        percent: 10,
        memoryBytes: ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES + 1,
      },
    ],
  }),
);
await assert.rejects(
  new ZkHolderReferenceProverClient(() => memoryHarness.worker).prove({
    fixtureId,
    expectedPublicSignals: publicSignals,
    maxMemoryBytes: ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES,
  }),
  expectCode("resource-limit"),
);

// Phase and percentage rollback fail closed before an engine can forge friendly progress.
const rollbackHarness = harness(
  successfulEngine({
    progress: [
      { phase: "proving", percent: 70, memoryBytes: 20_000_000 },
      { phase: "building-witness", percent: 80, memoryBytes: 20_000_000 },
    ],
  }),
);
await assert.rejects(
  new ZkHolderReferenceProverClient(() => rollbackHarness.worker).prove({
    fixtureId,
    expectedPublicSignals: publicSignals,
  }),
  expectCode("proving-failed"),
);

// A verified result that changes even one public signal is rejected inside the worker.
const changedSignals = [...publicSignals];
changedSignals[13] += 1n;
const mismatchHarness = harness(successfulEngine({ resultSignals: changedSignals }));
await assert.rejects(
  new ZkHolderReferenceProverClient(() => mismatchHarness.worker).prove({
    fixtureId,
    expectedPublicSignals: publicSignals,
  }),
  expectCode("proving-failed"),
);

const falseVerificationHarness = harness(successfulEngine({ proofVerified: false }));
await assert.rejects(
  new ZkHolderReferenceProverClient(() => falseVerificationHarness.worker).prove({
    fixtureId,
    expectedPublicSignals: publicSignals,
  }),
  expectCode("proving-failed"),
);

// Host cancellation terminates a synchronous-WASM-capable Worker rather than trusting cooperative abort.
const cancellation = new AbortController();
const cancelHarness = harness({
  runReference: () => new Promise(() => undefined),
});
const cancelled = new ZkHolderReferenceProverClient(() => cancelHarness.worker).prove({
  fixtureId,
  expectedPublicSignals: publicSignals,
  signal: cancellation.signal,
});
cancellation.abort();
await assert.rejects(cancelled, expectCode("cancelled"));
assert(cancelHarness.terminated(), "cancellation must hard-terminate the dedicated worker");

let factoryCalled = false;
const preCancelled = new AbortController();
preCancelled.abort();
await assert.rejects(
  new ZkHolderReferenceProverClient(() => {
    factoryCalled = true;
    return harness(successfulEngine()).worker;
  }).prove({ fixtureId, expectedPublicSignals: publicSignals, signal: preCancelled.signal }),
  expectCode("cancelled"),
);
assert.equal(factoryCalled, false, "a pre-cancelled request must not create a worker");

// Cancellation racing with Worker creation is observed even though adding an abort listener is not retroactive.
const creationRaceCancellation = new AbortController();
const creationRaceHarness = harness(successfulEngine());
await assert.rejects(
  new ZkHolderReferenceProverClient(() => {
    creationRaceCancellation.abort();
    return creationRaceHarness.worker;
  }).prove({
    fixtureId,
    expectedPublicSignals: publicSignals,
    signal: creationRaceCancellation.signal,
  }),
  expectCode("cancelled"),
);
assert(creationRaceHarness.terminated(), "cancellation during Worker creation must terminate the worker");
assert.equal(creationRaceHarness.hostMessages.length, 1, "only best-effort cancellation may cross the race");
assert.equal(parseZkHolderReferenceProverCommand(creationRaceHarness.hostMessages[0]).kind, "cancel");

// Strict parsing rejects extension fields and any attempt to relabel a receipt as presentable.
assert.throws(
  () => parseZkHolderReferenceProverCommand({ ...(completeHarness.hostMessages[0] as object), privateWitness: "x" }),
  /fields are invalid/u,
);
assert.throws(
  () => parseZkHolderReferenceProvingReceipt({ ...receipt, presentationReady: true }),
  /presentation-enabled/u,
);
assert.throws(
  () => parseZkHolderReferenceProvingReceipt({ ...receipt, profileStatus: "production-approved" }),
  /presentation-enabled/u,
);
assert.throws(
  () =>
    new ZkHolderReferenceProverClient(() => harness(successfulEngine()).worker).prove({
      fixtureId,
      expectedPublicSignals: publicSignals,
      unknown: true,
    } as never),
  /fields are invalid/u,
);

// An already-expired command receives only a bounded deadline code; the engine is never called.
const expiredMessages: unknown[] = [];
let expiredEngineCalled = false;
const expiredScope: ZkHolderReferenceWorkerScopeLike = {
  onmessage: null,
  postMessage: (message) => expiredMessages.push(message),
};
serveZkHolderReferenceProverWorker(expiredScope, {
  runReference() {
    expiredEngineCalled = true;
    throw new Error("must not run");
  },
});
assert(startCommand.kind === "start");
expiredScope.onmessage?.({ data: { ...startCommand, deadlineAtMs: 1 } });
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(expiredEngineCalled, false);
const expiredEvent = parseZkHolderReferenceProverEvent(expiredMessages[0]);
assert(expiredEvent.kind === "failed");
assert.equal(expiredEvent.code, "deadline-exceeded");

console.log("zk holder reference prover worker: isolation + cancellation + limits PASS");
