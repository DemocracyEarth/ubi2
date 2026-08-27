import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import init, {
  buildPackedStatusPath,
  validatePackedStatusSnapshot,
  verifyProductionVaultPayload,
  wasmLinearMemoryBytes,
} from "../browser/holder-refresh-engine-bindings.f22864b136562cf7d8a8d2c4ab6a16f9c01bd157feaa27b5129d5b741c399feb.js";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";
import { parseZkIdentityPackedStatusSnapshot } from "./zk-identity-status-snapshot";
import {
  createZkHolderPrivateStatusRefreshBrowserClient,
  ZkHolderPrivateStatusRefreshBrowserWasmEngine,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_BINDINGS_SHA256,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_BYTES,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_NAME,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256,
  type ZkHolderPrivateStatusRefreshBrowserWorkerConstructor,
  type ZkHolderPrivateStatusRefreshWasmPackage,
} from "./zk-holder-private-status-refresh-browser-runtime";
import {
  ZkHolderPrivateStatusRefreshClient,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_MEMORY_BYTES,
  type ZkHolderPrivateStatusRefreshPolicy,
  type ZkHolderPrivateStatusRefreshWorkerLike,
} from "./zk-holder-private-status-refresh";
import {
  parseZkHolderProductionVaultPayload,
  ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
} from "./zk-holder-production-vault";
import { ZK_HOLDER_PROFILE_ID } from "./zk-holder-profile-prover-worker";

const repository = new URL("../../../", import.meta.url);
const wasmPath = new URL(
  `fixtures/v2-production-crypto/holder-refresh-engine.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256}.wasm`,
  repository,
);
const wasmFile = await readFile(wasmPath);
const wasmBytes = Uint8Array.from(wasmFile);
assert.equal(wasmBytes.byteLength, ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_BYTES);
assert.equal(sha256(wasmBytes), ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256);
await init({ module_or_path: wasmBytes });

const contract = JSON.parse(
  await readFile(new URL("fixtures/v2-identity/production-vault-status-v1.json", repository), "utf8"),
) as { payload: Record<string, unknown> };
const payload = parseZkHolderProductionVaultPayload(contract.payload);
const snapshotText = await readFile(
  new URL("tools/v2-crypto-bench/fixtures/packed-status-snapshot.json", repository),
  "utf8",
);
const snapshot = parseZkIdentityPackedStatusSnapshot(JSON.parse(snapshotText));

// The real committed WASM executes the ratified vector, signature, subgroup
// and sparse-path checks. These are not JavaScript reimplementations.
assert.doesNotThrow(() => verifyProductionVaultPayload(JSON.stringify(payload)));
const badSignature = structuredClone(payload);
badSignature.issuerAuthentication.responseScalar = "1";
assert.throws(() => verifyProductionVaultPayload(JSON.stringify(badSignature)));
const torsion = structuredClone(payload);
torsion.issuerAuthentication.issuerPublicKey = {
  x: "0",
  y: (BN254_SCALAR_FIELD - 1n).toString(),
};
assert.throws(() => verifyProductionVaultPayload(JSON.stringify(torsion)));
assert.doesNotThrow(() => validatePackedStatusSnapshot(snapshotText));
const realPath = JSON.parse(buildPackedStatusPath(snapshotText, 2)) as {
  chunkLimbsLittleEndian: string[];
  siblingsBottomUp: string[];
};
assert.deepEqual(realPath.chunkLimbsLittleEndian, [
  (2n ** 128n - 5n).toString(),
  (2n ** 128n - 1n).toString(),
]);
assert.equal(realPath.siblingsBottomUp.length, 24);
assert.throws(() => buildPackedStatusPath(snapshotText, 1), "revoked status must fail closed");
const wrongRoot = JSON.parse(snapshotText) as Record<string, unknown>;
wrongRoot.root = `0x${"01".padStart(64, "0")}`;
assert.throws(() => validatePackedStatusSnapshot(JSON.stringify(wrongRoot)));

const actualPackage: ZkHolderPrivateStatusRefreshWasmPackage = {
  wasmSha256: ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256,
  bindingsSha256: ZK_HOLDER_PRIVATE_STATUS_REFRESH_BINDINGS_SHA256,
  bindings: {
    buildPackedStatusPath,
    validatePackedStatusSnapshot,
    verifyProductionVaultPayload,
    wasmLinearMemoryBytes,
  },
};
const policy: ZkHolderPrivateStatusRefreshPolicy = {
  profileId: ZK_HOLDER_PROFILE_ID,
  parameterManifestSha256: ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  productionApproved: true,
  cohorts: [],
};
const network = Object.fromEntries(
  ["fetch", "XMLHttpRequest", "WebSocket", "EventSource", "WebTransport", "importScripts"]
    .map((key) => [key, () => "network was reachable"]),
) as Record<string, unknown>;
const engine = new ZkHolderPrivateStatusRefreshBrowserWasmEngine(() => actualPackage, network);
assert.equal(ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED, false);
assert.equal(engine.admitsProductionProfile(policy), false, "the independent-audit gate remains closed");
await engine.validateSnapshot(snapshot, new AbortController().signal);
engine.lockNetwork();
for (const key of Object.keys(network)) {
  assert.throws(() => (network[key] as () => unknown)(), /disabled/u);
  assert.throws(() => Object.defineProperty(network, key, { value: () => undefined }));
}
await engine.verifyPayload(payload, new AbortController().signal);
assert.deepEqual(
  await engine.buildStatusPath({ snapshot, statusId: 2, signal: new AbortController().signal }),
  realPath,
);
assert(engine.memoryBytes() > 0 && engine.memoryBytes() <= ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_MEMORY_BYTES);
engine.destroy();

// Artifact substitution and excessive linear memory fail before private work.
const wrongArtifact = new ZkHolderPrivateStatusRefreshBrowserWasmEngine(() => ({
  ...actualPackage,
  wasmSha256: "0".repeat(64) as typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256,
}));
await assert.rejects(
  wrongArtifact.validateSnapshot(snapshot, new AbortController().signal),
  /content address/u,
);
const excessiveMemory = new ZkHolderPrivateStatusRefreshBrowserWasmEngine(() => ({
  ...actualPackage,
  bindings: { ...actualPackage.bindings, wasmLinearMemoryBytes: () => ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_MEMORY_BYTES + 1 },
}));
await assert.rejects(
  excessiveMemory.validateSnapshot(snapshot, new AbortController().signal),
  /memory/u,
);

// Cancellation is observed both before loading and after an in-flight loader
// resolves; no circuit entry point runs after the abort.
let loads = 0;
const preAbortEngine = new ZkHolderPrivateStatusRefreshBrowserWasmEngine(() => {
  loads += 1;
  return actualPackage;
});
const preAbort = new AbortController();
preAbort.abort();
await assert.rejects(preAbortEngine.validateSnapshot(snapshot, preAbort.signal), /cancelled/u);
assert.equal(loads, 0);
let resolveLoader!: (value: ZkHolderPrivateStatusRefreshWasmPackage) => void;
let snapshotCalls = 0;
const delayedPackage: ZkHolderPrivateStatusRefreshWasmPackage = {
  ...actualPackage,
  bindings: {
    ...actualPackage.bindings,
    validatePackedStatusSnapshot() { snapshotCalls += 1; },
  },
};
const delayedEngine = new ZkHolderPrivateStatusRefreshBrowserWasmEngine(() => new Promise((resolve) => {
  resolveLoader = resolve;
}));
const midAbort = new AbortController();
const pending = delayedEngine.validateSnapshot(snapshot, midAbort.signal);
midAbort.abort();
resolveLoader(delayedPackage);
await assert.rejects(pending, /cancelled/u);
assert.equal(snapshotCalls, 0);

// Runtime URLs must be same-origin and carry the exact reviewed source digest.
const locationDescriptor = Object.getOwnPropertyDescriptor(globalThis, "location");
Object.defineProperty(globalThis, "location", {
  value: { origin: "https://holder.invalid" },
  configurable: true,
});
try {
  const WorkerConstructor = class {
    constructor(
      _url: URL,
      _options: { type: "module"; name: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_NAME },
    ) {
      return {
        onmessage: null,
        onerror: null,
        postMessage() {},
        terminate() {},
      } satisfies ZkHolderPrivateStatusRefreshWorkerLike;
    }
  } as unknown as ZkHolderPrivateStatusRefreshBrowserWorkerConstructor;
  const correctUrl = new URL(
    `https://holder.invalid/assets/holder-private-status-refresh-worker.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256}.js`,
  );
  assert(createZkHolderPrivateStatusRefreshBrowserClient({
    workerUrl: correctUrl,
    WorkerConstructor,
  }) instanceof ZkHolderPrivateStatusRefreshClient);
  assert.throws(() => createZkHolderPrivateStatusRefreshBrowserClient({
    workerUrl: new URL("https://holder.invalid/assets/holder-private-status-refresh-worker.latest.js"),
    WorkerConstructor,
  }), /content-addressed/u);
  assert.throws(() => createZkHolderPrivateStatusRefreshBrowserClient({
    workerUrl: new URL(correctUrl.href.replace("holder.invalid", "cdn.invalid")),
    WorkerConstructor,
  }), /same-origin/u);
} finally {
  if (locationDescriptor) Object.defineProperty(globalThis, "location", locationDescriptor);
  else Reflect.deleteProperty(globalThis, "location");
}

// The checked-in package manifest and source bytes are independently pinned.
const manifest = JSON.parse(await readFile(
  new URL("fixtures/v2-production-crypto/holder-refresh-engine-artifacts-v1.json", repository),
  "utf8",
)) as { productionApproved: boolean; worker: { sourceSha256: string; sourceBytes: number }; artifacts: { path: string; sha256: string; bytes: number }[] };
assert.equal(manifest.productionApproved, false);
const workerSource = await readFile(
  new URL("tools/v2-crypto-bench/browser/holder-private-status-refresh-worker.ts", repository),
);
assert.equal(workerSource.byteLength, manifest.worker.sourceBytes);
assert.equal(sha256(workerSource), manifest.worker.sourceSha256);
assert.equal(manifest.worker.sourceSha256, ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256);
assert(!workerSource.toString("utf8").includes("console."));
for (const artifact of manifest.artifacts) {
  const bytes = await readFile(new URL(artifact.path, repository));
  assert.equal(bytes.byteLength, artifact.bytes, artifact.path);
  assert.equal(sha256(bytes), artifact.sha256, artifact.path);
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

console.log("zk holder refresh browser runtime: real WASM + subgroup + path + isolation + cancellation PASS");
