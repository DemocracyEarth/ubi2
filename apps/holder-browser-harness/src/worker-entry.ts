import { servePinnedHolderPrivateStatusRefreshWorker } from "../../../tools/v2-crypto-bench/browser/holder-private-status-refresh-worker";
import type { ZkHolderPrivateStatusRefreshWorkerScopeLike } from "@ubi2/sdk";
import { HARNESS_POLICY } from "./policy";

servePinnedHolderPrivateStatusRefreshWorker(
  globalThis as unknown as ZkHolderPrivateStatusRefreshWorkerScopeLike,
  HARNESS_POLICY,
);
