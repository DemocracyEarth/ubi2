import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  createZkHolderProfileBrowserClient,
  parseZkHolderProfileBrowserReport,
  serveZkHolderProfileBrowserWorker,
  ZK_HOLDER_PROFILE_BROWSER_CONSTRAINTS,
  ZK_HOLDER_PROFILE_BROWSER_REPORT_SCHEMA,
  ZK_HOLDER_PROFILE_BROWSER_WITNESS_VARIABLES,
  ZK_HOLDER_PROFILE_BROWSER_WORKER_NAME,
  ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS,
  type ZkHolderProfileBrowserWasmBindings,
  type ZkHolderProfileBrowserWorkerConstructor,
} from "./zk-holder-profile-browser-runtime";
import {
  ZkHolderProfileProverClient,
  ZkHolderProfileProverError,
  ZK_HOLDER_PROFILE_ID,
  ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID,
  ZK_HOLDER_PROFILE_SYNTHETIC_WARNING,
  ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256,
  type ZkHolderProfileWorkerLike,
  type ZkHolderProfileWorkerScopeLike,
} from "./zk-holder-profile-prover-worker";
import { syntheticProfileVaultFixture } from "./zk-holder-profile-test-fixture";

const wasmBytes = new Uint8Array(await readFile(new URL("../../../fixtures/v2-production-crypto/holder-profile-synthetic-v1.wasm", import.meta.url)));
const fixture = await syntheticProfileVaultFixture();

function report(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    schema: ZK_HOLDER_PROFILE_BROWSER_REPORT_SCHEMA,
    profileId: ZK_HOLDER_PROFILE_ID,
    warning: ZK_HOLDER_PROFILE_SYNTHETIC_WARNING,
    constraints: ZK_HOLDER_PROFILE_BROWSER_CONSTRAINTS,
    witnessVariables: ZK_HOLDER_PROFILE_BROWSER_WITNESS_VARIABLES,
    publicInputCount: 18,
    publicInputs: ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS.map(String),
    proof: {
      a: { x: "1", y: "2" },
      b: { x_imaginary: "3", x_real: "4", y_imaginary: "5", y_real: "6" },
      c: { x: "7", y: "8" },
    },
    proofVerified: true,
    ...overrides,
  });
}

function bindings(options?: { report?: string; onCredential?: (value: unknown) => void; onDestroy?: () => void; memory?: readonly number[] }): ZkHolderProfileBrowserWasmBindings {
  let reads = 0;
  const memory = options?.memory ?? [32 * 1024 * 1024, 96 * 1024 * 1024];
  return {
    proveSyntheticHolderProfile(privateCredentialJson) {
      options?.onCredential?.(JSON.parse(privateCredentialJson));
      return options?.report ?? report();
    },
    wasmLinearMemoryBytes() {
      const value = memory[Math.min(reads, memory.length - 1)]!;
      reads += 1;
      return value;
    },
    destroy: options?.onDestroy,
  };
}

interface Harness { worker: ZkHolderProfileWorkerLike; hostEnvelope: unknown; workerMessages: unknown[]; terminated(): boolean }
function harness(loader: (bytes: Uint8Array) => ZkHolderProfileBrowserWasmBindings | Promise<ZkHolderProfileBrowserWasmBindings>): Harness {
  let stopped = false;
  let hostEnvelope: unknown;
  const workerMessages: unknown[] = [];
  const worker: ZkHolderProfileWorkerLike = {
    onmessage: null,
    onerror: null,
    postMessage(message, transfer = []) {
      const delivered = structuredClone(message, { transfer: [...transfer] });
      if ((delivered as { kind?: string }).kind === "start") {
        const command = delivered as { vault: unknown; profile: unknown };
        hostEnvelope = { vault: structuredClone(command.vault), profile: structuredClone(command.profile) };
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
  serveZkHolderProfileBrowserWorker(scope, loader);
  return { worker, get hostEnvelope() { return hostEnvelope; }, workerMessages, terminated: () => stopped };
}

function request(artifact = wasmBytes) {
  return {
    profile: { mode: "synthetic" as const, profileId: ZK_HOLDER_PROFILE_ID, fixtureId: ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID },
    artifacts: [{ role: "wasmModule" as const, sha256: ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256, bytes: artifact }],
    vault: fixture.vault,
    unlock: { credentialId: fixture.credentialId, prfOutput: fixture.prfOutput },
    expectedPublicSignals: ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS,
  };
}

function expectCode(code: ZkHolderProfileProverError["code"]) {
  return (error: unknown) => error instanceof ZkHolderProfileProverError && error.code === code;
}

assert.deepEqual(parseZkHolderProfileBrowserReport(report()).publicInputs, ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS);
let loadCount = 0;
let credentialSeen: unknown;
let destroyCount = 0;
const complete = harness((verifiedBytes) => {
  loadCount += 1;
  assert.equal(verifiedBytes.byteLength, wasmBytes.byteLength);
  assert.deepEqual(verifiedBytes.slice(0, 8), wasmBytes.slice(0, 8));
  return bindings({ onCredential: (value) => (credentialSeen = value), onDestroy: () => (destroyCount += 1) });
});
const receipt = await new ZkHolderProfileProverClient(() => complete.worker).prove(request());
assert.equal(loadCount, 1);
assert.equal(destroyCount, 1);
assert(complete.terminated());
assert.deepEqual(credentialSeen, fixture.payload.credential, "only Worker-private code receives vault plaintext");
assert.equal(receipt.proof, `0x${[1, 2, 3, 4, 5, 6, 7, 8].map((word) => word.toString(16).padStart(64, "0")).join("")}`);
assert.equal(receipt.locallyVerified, true);
assert.equal(receipt.presentationReady, false);
const crossedBoundary = JSON.stringify({ host: complete.hostEnvelope, events: complete.workerMessages, receipt });
for (const privateValue of ["holderSecret", "credentialBlinding", "dateOfBirth", "nationality", "2000-01-01", "XAA"]) {
  assert(!crossedBoundary.includes(privateValue), `Worker messages must omit ${privateValue}`);
}

// Browser construction remains same-origin and uses a dedicated named module Worker.
let createdUrl: URL | undefined;
let createdOptions: { type: "module"; name: typeof ZK_HOLDER_PROFILE_BROWSER_WORKER_NAME } | undefined;
const constructorHarness = harness(() => bindings());
const TestWorker = class {
  constructor(url: URL, options: { type: "module"; name: typeof ZK_HOLDER_PROFILE_BROWSER_WORKER_NAME }) {
    createdUrl = url;
    createdOptions = options;
    return constructorHarness.worker;
  }
} as unknown as ZkHolderProfileBrowserWorkerConstructor;
const client = createZkHolderProfileBrowserClient({
  workerUrl: new URL("https://holder.invalid/assets/profile-worker.1a931e60.js"),
  WorkerConstructor: TestWorker,
});
await client.prove(request());
assert.equal(createdUrl?.href, "https://holder.invalid/assets/profile-worker.1a931e60.js");
assert.deepEqual(createdOptions, { type: "module", name: ZK_HOLDER_PROFILE_BROWSER_WORKER_NAME });
assert.throws(() => createZkHolderProfileBrowserClient({ workerUrl: new URL("data:text/javascript,1"), WorkerConstructor: TestWorker }), /HTTP or HTTPS/u);
assert.throws(() => createZkHolderProfileBrowserClient({ workerUrl: new URL("https://user:pass@holder.invalid/worker.js"), WorkerConstructor: TestWorker }), /credentials or a fragment/u);

// Hash rejection occurs before the WASM loader or vault parser runs.
const changedWasm = new Uint8Array(wasmBytes);
changedWasm[10] ^= 1;
let changedLoaded = false;
const mismatch = harness(() => { changedLoaded = true; return bindings(); });
await assert.rejects(new ZkHolderProfileProverClient(() => mismatch.worker).prove(request(changedWasm)), expectCode("artifact-hash-mismatch"));
assert.equal(changedLoaded, false);

// Malicious reports cannot relabel, extend or change proof/public-input data.
const changedSignals = ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS.map(String);
changedSignals[13] = (ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS[13]! + 1n).toString();
for (const bad of [
  report({ proofVerified: false }),
  report({ profileId: "org.proofofhumanity.production/forged" }),
  report({ publicInputs: changedSignals }),
  report({ proof: { a: { x: "01", y: "2" }, b: { x_imaginary: "3", x_real: "4", y_imaginary: "5", y_real: "6" }, c: { x: "7", y: "8" } } }),
  report({ privateCredential: "must-not-cross" }),
]) {
  const badHarness = harness(() => bindings({ report: bad }));
  await assert.rejects(new ZkHolderProfileProverClient(() => badHarness.worker).prove(request()), expectCode("proving-failed"));
}

await assert.rejects(
  new ZkHolderProfileProverClient(() => harness(() => bindings()).worker).prove({
    ...request(),
    unlock: { credentialId: fixture.credentialId, prfOutput: new Uint8Array(32).fill(0x98) },
  }),
  expectCode("vault-unlock-failed"),
);

console.log("zk holder profile browser runtime: verified WASM + private ingress + proof output PASS");
