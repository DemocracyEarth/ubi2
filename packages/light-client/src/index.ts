/**
 * @ubi2/light-client — ubi2 browser/Node light node.
 *
 * Connects to a WebSocket sync gateway (`ws://<node>/sync`), exchanges the M5 `ubi2/sync/1`
 * `SyncRequest`/`SyncResponse` binary messages, drives the `crates/runtime-wasm` WASM kernel to
 * re-execute each block and assert a byte-identical `state_root`, and exposes verified reads
 * (`balanceOf`, `humanStatus`, `tip`) from locally re-executed state.
 *
 * A separate package from `@ubi2/sdk` (spec 07 §11 / ADR-0006 Decision 1): the SDK stays a thin
 * RPC/encoder client with no WASM blob; non-light-node consumers don't pull the WASM artifact.
 * The light client depends on the SDK for `projectBalance` and `EMISSION_RATE`.
 *
 * Trust model: full re-execution from genesis (or a restored IndexedDB snapshot).  A forged block
 * from the gateway is caught by the WASM kernel (verification error, never a wrong balance).
 */

export { LightClient, VerificationError, WrongNetworkError, GatewayError } from "./client.js";
export type { LightClientOptions, VerifiedBalanceSample, VerifyMode } from "./client.js";
export type {
  ILightState,
  LightStateFactory,
  LightStateGenesisFactory,
  BlockOutcome,
  TipInfo,
} from "./wasm-types.js";
export {
  defaultStore,
  InMemoryStore,
  IndexedDbStore,
} from "./store.js";
export type { SnapshotStore } from "./store.js";

// Wire codec (public for tests and tooling).
export {
  encodeSyncRequest,
  decodeSyncResponse,
  encodeWireBlock,
  decodeWireBlock,
  encodeHello,
  decodeHello,
  encodeGetBlocks,
  decodeGetBlocks,
  encodeBlocks,
  decodeBlocks,
  encodeGenesis,
  decodeGenesis,
  toHex,
  fromHex,
  bytesEqual,
} from "./wire.js";
export type {
  WireBlock,
  Hello,
  GetBlocks,
  Blocks,
  Genesis,
  SyncRequest,
  SyncResponse,
} from "./wire.js";

// Re-export SDK utilities useful in light-client contexts (projectBalance, formatUbi, EMISSION_RATE).
export { projectBalance, formatUbi, EMISSION_RATE, EMISSION_PERIOD_SECS } from "@ubi2/sdk";
