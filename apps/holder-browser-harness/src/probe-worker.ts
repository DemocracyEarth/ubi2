/// <reference lib="webworker" />
import snapshotText from "../../../tools/v2-crypto-bench/fixtures/packed-status-snapshot.json?raw";
import { lockWorkerNetwork } from "@ubi2/sdk";
import { loadPinnedHolderPrivateStatusRefreshWasm } from "../../../tools/v2-crypto-bench/browser/holder-private-status-refresh-worker";

declare const self: DedicatedWorkerGlobalScope;

self.onmessage = (event: MessageEvent<unknown>) => {
  if (!event.data || typeof event.data !== "object" || (event.data as { type?: unknown }).type !== "run-public-probe") {
    self.postMessage({ status: "rejected" });
    self.close();
    return;
  }
  void run();
};

async function run(): Promise<void> {
  const started = performance.now();
  try {
    const packageValue = await loadPinnedHolderPrivateStatusRefreshWasm();
    lockWorkerNetwork(globalThis as unknown as Record<string, unknown>);
    packageValue.bindings.validatePackedStatusSnapshot(snapshotText);
    const path = JSON.parse(packageValue.bindings.buildPackedStatusPath(snapshotText, 2)) as {
      siblingsBottomUp: unknown[];
    };
    self.postMessage({
      status: "ok",
      wasmSha256: packageValue.wasmSha256,
      bindingsSha256: packageValue.bindingsSha256,
      memoryBytes: packageValue.bindings.wasmLinearMemoryBytes(),
      siblingCount: path.siblingsBottomUp.length,
      elapsedMs: performance.now() - started,
      networkLocked: networkIsLocked(),
    });
  } catch (error) {
    self.postMessage({ status: "failed", message: error instanceof Error ? error.message : "probe failed" });
  } finally {
    self.close();
  }
}

function networkIsLocked(): boolean {
  try { void fetch("/private/forbidden"); } catch { return true; }
  return false;
}
