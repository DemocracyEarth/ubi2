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
  /**
   * Re-pin the PoA validator set after a snapshot restore (`ln-trust-1`).  Optional on the interface
   * (the WASM `LightState` always provides it); a restored session re-supplies its pinned set so
   * proposer authority is enforced on the next block.
   */
  setValidatorSet?(validatorSet: string[]): void;
}

/**
 * Legacy factory: constructs an EMPTY-state `LightState` anchored at a genesis hash/root (the pre-pin
 * path).  RETAINED for back-compat / tests, but the shipped client uses {@link LightStateGenesisFactory}
 * with a PINNED, verified seeded-genesis snapshot — the empty-state path is non-functional on a real
 * seeded chain (`ln-trust-2`).
 */
export type LightStateFactory = (
  chainId: number,
  genesisHash: string,
  genesisStateRoot: string,
  genesisTime: number,
) => ILightState;

/**
 * Factory: constructs a `LightState` from a **pinned, gateway-independent genesis anchor** (spec 07
 * §3.4 — the `ln-trust-1/2/3` fix).  `genesisSnapshot` is the seeded genesis state the gateway served
 * (untrusted bytes); `pinnedStateRoot` is the app's HARD-CODED genesis state_root constant.  The kernel
 * re-derives the snapshot's root LOCALLY and THROWS unless it equals `pinnedStateRoot` (so a lying
 * gateway is caught).  `validatorSet` is the pinned PoA proposer set, enforced on every block.
 */
export type LightStateGenesisFactory = (
  chainId: number,
  genesisHash: string,
  pinnedStateRoot: string,
  genesisTime: number,
  genesisSnapshot: Uint8Array,
  validatorSet: string[],
) => ILightState;
