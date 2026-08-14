import init, {
  generateRegistryProvingKey,
  proveRegistryDepth,
  wasmLinearMemoryBytes,
} from "./pkg/ubi2_v2_crypto_bench.js";

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

self.onmessage = async ({ data }) => {
  try {
    await init();
    const initialMemoryBytes = wasmLinearMemoryBytes();
    const started = performance.now();

    if (data.phase === "setup") {
      const provingKey = generateRegistryProvingKey(data.depth);
      const elapsedMs = performance.now() - started;
      const retainedMemoryBytes = wasmLinearMemoryBytes();
      const provingKeyBuffer = provingKey.buffer.slice(
        provingKey.byteOffset,
        provingKey.byteOffset + provingKey.byteLength,
      );
      const provingKeySha256 = await sha256Hex(provingKeyBuffer);
      self.postMessage(
        {
          ok: true,
          phase: data.phase,
          depth: data.depth,
          elapsedMs,
          initialMemoryBytes,
          retainedMemoryBytes,
          provingKeyBytes: provingKey.byteLength,
          provingKeySha256,
          provingKeyBuffer,
        },
        [provingKeyBuffer],
      );
      return;
    }

    if (data.phase === "prove") {
      const provingKeySha256 = await sha256Hex(data.provingKeyBuffer);
      if (provingKeySha256 !== data.expectedProvingKeySha256) {
        throw new Error("Proving-key fingerprint changed during worker transfer");
      }
      const report = JSON.parse(
        proveRegistryDepth(data.depth, new Uint8Array(data.provingKeyBuffer)),
      );
      self.postMessage({
        ok: true,
        phase: data.phase,
        depth: data.depth,
        elapsedMs: performance.now() - started,
        initialMemoryBytes,
        retainedMemoryBytes: wasmLinearMemoryBytes(),
        provingKeySha256,
        report,
      });
      return;
    }

    throw new Error(`Unknown benchmark phase: ${data.phase}`);
  } catch (error) {
    self.postMessage({
      ok: false,
      phase: data.phase,
      depth: data.depth,
      error: error instanceof Error ? error.message : String(error),
    });
  }
};
