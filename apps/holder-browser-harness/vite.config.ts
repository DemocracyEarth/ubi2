import { copyFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import { ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256, ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256 } from "../../packages/sdk/src/zk-holder-private-status-refresh-browser-runtime";

const root = resolve(import.meta.dirname, "../..");
const workerStem = `holder-private-status-refresh-worker.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256}`;

function copyContentAddressedWasm(): Plugin {
  return {
    name: "copy-content-addressed-holder-refresh-wasm",
    generateBundle(_options, bundle) {
      for (const filename of Object.keys(bundle)) {
        if (
          filename.startsWith(`assets/holder-refresh-engine.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256}-`) &&
          filename.endsWith(".wasm")
        ) delete bundle[filename];
      }
    },
    async closeBundle() {
      const destinationDirectory = resolve(import.meta.dirname, "dist/fixtures/v2-production-crypto");
      await mkdir(destinationDirectory, { recursive: true });
      const filename = `holder-refresh-engine.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256}.wasm`;
      await copyFile(resolve(root, "fixtures/v2-production-crypto", filename), resolve(destinationDirectory, filename));
    },
  };
}

export default defineConfig({
  plugins: [copyContentAddressedWasm()],
  experimental: {
    renderBuiltUrl(filename) {
      if (filename.includes(`holder-refresh-engine.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256}`)) {
        return `/fixtures/v2-production-crypto/holder-refresh-engine.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256}.wasm`;
      }
      return { relative: true };
    },
  },
  build: {
    target: "es2022",
    assetsInlineLimit: 0,
    rollupOptions: {
      input: {
        app: resolve(import.meta.dirname, "index.html"),
        [workerStem]: resolve(import.meta.dirname, "src/worker-entry.ts"),
      },
      output: {
        entryFileNames: (chunk) => chunk.name === workerStem ? `assets/${workerStem}.js` : "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});
