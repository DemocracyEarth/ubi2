/**
 * Content-addressed ADR-0014 Worker entry package.
 *
 * A deployment bundles this source to the exact filename required by
 * createZkHolderPrivateStatusRefreshBrowserClient. The WASM bytes are fetched
 * once from the same origin, length/hash checked, compiled, and initialized
 * before the runtime removes network capabilities and decrypts any vault.
 */
import init, {
  buildPackedStatusPath,
  validatePackedStatusSnapshot,
  verifyProductionVaultPayload,
  wasmLinearMemoryBytes,
} from "../../../packages/sdk/browser/holder-refresh-engine-bindings.f22864b136562cf7d8a8d2c4ab6a16f9c01bd157feaa27b5129d5b741c399feb.js";
import {
  serveZkHolderPrivateStatusRefreshBrowserWorker,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_BINDINGS_SHA256,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_BYTES,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256,
  type ZkHolderPrivateStatusRefreshWasmPackage,
} from "../../../packages/sdk/src/zk-holder-private-status-refresh-browser-runtime";
import type {
  ZkHolderPrivateStatusRefreshPolicy,
  ZkHolderPrivateStatusRefreshWorkerScopeLike,
} from "../../../packages/sdk/src/zk-holder-private-status-refresh";

const WASM_URL = new URL(
  `../../../fixtures/v2-production-crypto/holder-refresh-engine.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256}.wasm`,
  import.meta.url,
);

let loading: Promise<ZkHolderPrivateStatusRefreshWasmPackage> | undefined;

export function loadPinnedHolderPrivateStatusRefreshWasm(): Promise<ZkHolderPrivateStatusRefreshWasmPackage> {
  loading ??= loadAndVerify();
  return loading;
}

/**
 * Install the Worker handler with the production bit forcibly disabled. The
 * independent-audit admission slice must change both this bit and the SDK's
 * compile-time audit constant in one separately reviewed diff.
 */
export function servePinnedHolderPrivateStatusRefreshWorker(
  scope: ZkHolderPrivateStatusRefreshWorkerScopeLike,
  reviewedPolicy: ZkHolderPrivateStatusRefreshPolicy,
  now?: () => number,
): void {
  serveZkHolderPrivateStatusRefreshBrowserWorker(scope, {
    policy: { ...reviewedPolicy, productionApproved: false },
    loadWasm: loadPinnedHolderPrivateStatusRefreshWasm,
    networkTarget: scope as unknown as Record<string, unknown>,
    now,
  });
}

async function loadAndVerify(): Promise<ZkHolderPrivateStatusRefreshWasmPackage> {
  const location = (globalThis as { location?: Location }).location;
  if (!location || WASM_URL.origin !== location.origin) {
    throw new Error("holder refresh WASM must be loaded from the Worker origin");
  }
  const response = await fetch(WASM_URL, {
    cache: "force-cache",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  if (!response.ok || response.type === "opaque") throw new Error("holder refresh WASM response was rejected");
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_BYTES) {
    throw new Error("holder refresh WASM length does not match its content address");
  }
  const digest = hex(await crypto.subtle.digest("SHA-256", bytes));
  if (digest !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256) {
    throw new Error("holder refresh WASM digest does not match its content address");
  }
  const module = await WebAssembly.compile(bytes);
  await init({ module_or_path: module });
  return {
    wasmSha256: ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256,
    bindingsSha256: ZK_HOLDER_PRIVATE_STATUS_REFRESH_BINDINGS_SHA256,
    bindings: {
      buildPackedStatusPath,
      validatePackedStatusSnapshot,
      verifyProductionVaultPayload,
      wasmLinearMemoryBytes,
    },
  };
}

function hex(value: ArrayBuffer): string {
  return Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
