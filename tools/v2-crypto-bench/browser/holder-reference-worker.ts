import init, {
  proveDynamicStatusReference,
  wasmLinearMemoryBytes,
} from "./pkg/ubi2_v2_crypto_bench.js";
import { serveZkHolderReferenceBrowserWorker } from "../../../packages/sdk/src/zk-holder-reference-browser-runtime";

serveZkHolderReferenceBrowserWorker(self, async () => {
  await init();
  return {
    proveDynamicStatusReference,
    wasmLinearMemoryBytes,
  };
});
