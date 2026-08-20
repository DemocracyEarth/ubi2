import init, {
  proveSyntheticHolderProfile,
  wasmLinearMemoryBytes,
} from "./pkg/ubi2_v2_crypto_bench.js";
import { serveZkHolderProfileBrowserWorker } from "../../../packages/sdk/src/zk-holder-profile-browser-runtime";

serveZkHolderProfileBrowserWorker(self, async (verifiedWasmModule) => {
  await init({ module_or_path: verifiedWasmModule });
  return { proveSyntheticHolderProfile, wasmLinearMemoryBytes };
});
