import assert from "node:assert/strict";
import {
  createZkHolderReferenceBrowserClient,
  parseZkHolderReferenceBrowserReport,
  serveZkHolderReferenceBrowserWorker,
  ZK_HOLDER_REFERENCE_BROWSER_CONSTRAINTS,
  ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
  ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
  ZK_HOLDER_REFERENCE_BROWSER_REPORT_SCHEMA,
  ZK_HOLDER_REFERENCE_BROWSER_REPORT_WARNING,
  ZK_HOLDER_REFERENCE_BROWSER_WITNESS_VARIABLES,
  ZK_HOLDER_REFERENCE_BROWSER_WORKER_NAME,
  type ZkHolderReferenceBrowserWasmBindings,
  type ZkHolderReferenceBrowserWorkerConstructor,
} from "./zk-holder-reference-browser-runtime";
import {
  ZkHolderReferenceProverClient,
  ZkHolderReferenceProverError,
  ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES,
  type ZkHolderReferenceProvingProgress,
  type ZkHolderReferenceWorkerLike,
  type ZkHolderReferenceWorkerScopeLike,
} from "./zk-holder-reference-prover-worker";

function report(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    schema: ZK_HOLDER_REFERENCE_BROWSER_REPORT_SCHEMA,
    warning: ZK_HOLDER_REFERENCE_BROWSER_REPORT_WARNING,
    constraints: ZK_HOLDER_REFERENCE_BROWSER_CONSTRAINTS,
    witness_variables: ZK_HOLDER_REFERENCE_BROWSER_WITNESS_VARIABLES,
    public_input_count: 18,
    public_inputs: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS.map(String),
    proof_verified: true,
    ...overrides,
  });
}

interface Harness {
  worker: ZkHolderReferenceWorkerLike;
  hostMessages: unknown[];
  workerMessages: unknown[];
  terminated(): boolean;
}

function harness(loadWasm: () => Promise<ZkHolderReferenceBrowserWasmBindings> | ZkHolderReferenceBrowserWasmBindings): Harness {
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
  serveZkHolderReferenceBrowserWorker(scope, loadWasm);
  return { worker, hostMessages, workerMessages, terminated: () => stopped };
}

function bindings(options?: {
  report?: string;
  memory?: readonly number[];
  onProve?: () => void;
  onDestroy?: () => void;
}): ZkHolderReferenceBrowserWasmBindings {
  let memoryRead = 0;
  const memory = options?.memory ?? [65_536, 90_308_608];
  return {
    proveDynamicStatusReference() {
      options?.onProve?.();
      return options?.report ?? report();
    },
    wasmLinearMemoryBytes() {
      const value = memory[Math.min(memoryRead, memory.length - 1)];
      memoryRead += 1;
      return value!;
    },
    destroy: options?.onDestroy,
  };
}

function expectCode(code: ZkHolderReferenceProverError["code"]) {
  return (error: unknown) => error instanceof ZkHolderReferenceProverError && error.code === code;
}

assert.equal(ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS.length, 18);
assert.deepEqual(
  parseZkHolderReferenceBrowserReport(report()).public_inputs,
  ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
);

let loadCount = 0;
let proveCount = 0;
let destroyCount = 0;
const completeHarness = harness(() => {
  loadCount += 1;
  return bindings({
    onProve: () => (proveCount += 1),
    onDestroy: () => (destroyCount += 1),
  });
});
const progress: ZkHolderReferenceProvingProgress[] = [];
const receipt = await new ZkHolderReferenceProverClient(() => completeHarness.worker).prove({
  fixtureId: ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
  expectedPublicSignals: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
  onProgress: (value) => progress.push(value),
});
assert.equal(loadCount, 1);
assert.equal(proveCount, 1);
assert.equal(destroyCount, 1);
assert.equal(receipt.presentationReady, false);
assert.equal(receipt.proofVerified, true);
assert.equal(receipt.peakMemoryBytes, 90_308_608);
assert(completeHarness.terminated(), "the real-browser adapter must retain one-worker-per-run isolation");
assert.deepEqual(
  progress.map(({ phase, percent }) => [phase, percent]),
  [
    ["initializing", 0],
    ["loading-artifacts", 5],
    ["loading-artifacts", 20],
    ["building-witness", 35],
    ["proving", 55],
    ["verifying", 95],
  ],
);
const crossedBoundary = JSON.stringify({
  host: completeHarness.hostMessages,
  worker: completeHarness.workerMessages,
  receipt,
});
for (const forbidden of [
  "privateCredential",
  "holderSecret",
  "credentialBlinding",
  "dateOfBirth",
  "nationality",
  "statusId",
  "proofBytes",
  "provingKey",
  "verificationKey",
]) {
  assert(!crossedBoundary.includes(forbidden), `browser Worker boundary must omit ${forbidden}`);
}

// The application supplies only a same-origin module Worker URL; no proof or artifact is a constructor option.
let constructedUrl: URL | undefined;
let constructedOptions: { type: "module"; name: typeof ZK_HOLDER_REFERENCE_BROWSER_WORKER_NAME } | undefined;
const constructorHarness = harness(() => bindings());
const TestWorker = class {
  constructor(
    url: URL,
    options: { type: "module"; name: typeof ZK_HOLDER_REFERENCE_BROWSER_WORKER_NAME },
  ) {
    constructedUrl = url;
    constructedOptions = options;
    return constructorHarness.worker;
  }
} as unknown as ZkHolderReferenceBrowserWorkerConstructor;
const browserClient = createZkHolderReferenceBrowserClient({
  workerUrl: new URL("https://holder.invalid/assets/reference-worker.js?v=sha256"),
  WorkerConstructor: TestWorker,
});
await browserClient.prove({
  fixtureId: ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
  expectedPublicSignals: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
});
assert.equal(constructedUrl?.href, "https://holder.invalid/assets/reference-worker.js?v=sha256");
assert.deepEqual(constructedOptions, { type: "module", name: ZK_HOLDER_REFERENCE_BROWSER_WORKER_NAME });

assert.throws(
  () =>
    createZkHolderReferenceBrowserClient({
      workerUrl: new URL("data:text/javascript,postMessage(1)"),
      WorkerConstructor: TestWorker,
    }),
  /HTTP or HTTPS/u,
);
assert.throws(
  () =>
    createZkHolderReferenceBrowserClient({
      workerUrl: new URL("https://user:password@holder.invalid/reference-worker.js"),
      WorkerConstructor: TestWorker,
    }),
  /credentials or a fragment/u,
);
assert.throws(
  () =>
    createZkHolderReferenceBrowserClient({
      workerUrl: new URL("https://holder.invalid/reference-worker.js#mutable"),
      WorkerConstructor: TestWorker,
    }),
  /credentials or a fragment/u,
);

// A different fixture vector fails before loading or running expensive WASM.
let mismatchedLoaderCalled = false;
const mismatchedSignals = [...ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS];
mismatchedSignals[13] += 1n;
const mismatchedHarness = harness(() => {
  mismatchedLoaderCalled = true;
  return bindings();
});
await assert.rejects(
  new ZkHolderReferenceProverClient(() => mismatchedHarness.worker).prove({
    fixtureId: ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
    expectedPublicSignals: mismatchedSignals,
  }),
  expectCode("proving-failed"),
);
assert.equal(mismatchedLoaderCalled, false);

// Report substitution, relabeling, unknown fields and false verification all fail closed.
const changedReportSignals = ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS.map(String);
changedReportSignals[13] = (ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS[13]! + 1n).toString();
for (const badReport of [
  report({ public_inputs: changedReportSignals }),
  report({ proof_verified: false }),
  report({ schema: "org.proofofhumanity.production/1" }),
  report({ proof: "must-not-cross" }),
  report({ public_inputs: ["01", ...ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS.slice(1).map(String)] }),
]) {
  const badHarness = harness(() => bindings({ report: badReport }));
  await assert.rejects(
    new ZkHolderReferenceProverClient(() => badHarness.worker).prove({
      fixtureId: ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
      expectedPublicSignals: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
    }),
    expectCode("proving-failed"),
  );
}

// Memory growth is checked after synchronous WASM returns and before any receipt can escape.
const memoryHarness = harness(() =>
  bindings({
    memory: [8 * 1024 * 1024, ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES + 1],
  }),
);
await assert.rejects(
  new ZkHolderReferenceProverClient(() => memoryHarness.worker).prove({
    fixtureId: ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
    expectedPublicSignals: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
    maxMemoryBytes: ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES,
  }),
  expectCode("resource-limit"),
);

// Loader/WASM errors collapse to a bounded code; their text never leaves the Worker.
const secretMarker = "synthetic-private-witness-must-not-leak";
const loaderFailureHarness = harness(() => {
  throw new Error(secretMarker);
});
await assert.rejects(
  new ZkHolderReferenceProverClient(() => loaderFailureHarness.worker).prove({
    fixtureId: ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID,
    expectedPublicSignals: ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS,
  }),
  (error: unknown) => {
    assert(expectCode("proving-failed")(error));
    assert(!String(error).includes(secretMarker));
    return true;
  },
);
assert(!JSON.stringify(loaderFailureHarness.workerMessages).includes(secretMarker));

console.log("zk holder reference browser runtime: real-WASM seam + isolation PASS");
