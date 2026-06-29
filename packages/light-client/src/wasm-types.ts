/**
 * TypeScript interface for the `LightState` WASM handle (crates/runtime-wasm/src/lib.rs).
 *
 * The actual WASM module is loaded at runtime from `crates/runtime-wasm` compiled with
 * wasm-pack / wasm-bindgen. This interface describes the JS-facing API exactly as the
 * #[wasm_bindgen] impl exports it (spec 07 §2.2).
 *
 * In tests (Node.js, no browser) we use a pure-JS shim (`WasmShim`) that satisfies this
 * interface without loading an actual WASM artifact — needed because:
 *   - The integration test runs under Node.js (not a browser).
 *   - The WASM artifact path depends on the build system.
 *
 * In production (browser), the caller initialises with `initLightState(wasmModule)` pointing
 * at the actual `wasm-bindgen`-generated JS glue.
 */

/** The outcome of a successfully applied block (returned by `applyBlock`). */
export interface BlockOutcome {
  number: number;
  hash: string; // 0x-hex
  stateRoot: string; // 0x-hex
  timestamp: number;
}

/** The verified chain tip (returned by `tip()`). */
export interface TipInfo {
  number: number;
  hash: string; // 0x-hex
  stateRoot: string; // 0x-hex
  timestamp: number;
}

/**
 * The WASM `LightState` handle interface.  Matches the `#[wasm_bindgen] impl LightState` in
 * `crates/runtime-wasm/src/lib.rs` exactly (spec §2.2).
 */
export interface ILightState {
  /** Re-execute + root-verify a canonical WireBlock.  Throws on any failure (fail-closed). */
  applyBlock(wire: Uint8Array, expectedProposer?: string): BlockOutcome;
  /** The 32-byte state_root as a 0x-hex string. */
  stateRoot(): string;
  /** The verified tip. */
  tip(): TipInfo;
  /** Streaming balance at unix-second `now`, as a decimal string of base units (never a float). */
  balanceOf(addr: string, now: bigint): string;
  /** Nonce of `addr`. */
  nonceOf(addr: string): number;
  /** PoH status byte of `addr` (0=Unverified…4=Revoked). */
  humanStatus(addr: string): number;
  /** Serialize the verified state + tip for IndexedDB persistence. */
  serialize(): Uint8Array;
}

/**
 * Factory: constructs a `LightState` anchored at genesis.  The factory is provided by the caller
 * so the light-client package stays WASM-agnostic — the browser supplies the actual
 * wasm-bindgen-generated class; Node tests supply a Rust-native shim via `LightCore` FFI or the
 * pure-JS shim below.
 */
export type LightStateFactory = (
  chainId: number,
  genesisHash: string,
  genesisStateRoot: string,
  genesisTime: number,
) => ILightState;
