/**
 * WASM loader shim — loads the wasm-pack "web" target artefacts from
 * packages/light-client/wasm/ and returns a LightStateFactory that the
 * LightClient constructor accepts.
 *
 * The wasm-pack --target web output has:
 *   - default export: init(url?) → Promise  (must be awaited before use)
 *   - named export: LightState class
 *
 * The generated constructor signature is:
 *   new LightState(chain_id: bigint, genesis_hash: string, genesis_state_root: string, genesis_time: bigint)
 *
 * The ILightState factory signature expects numbers for chain_id and genesis_time,
 * so we coerce them here at the adapter layer.
 */

import type { ILightState, LightStateFactory, BlockOutcome, TipInfo } from "@ubi2/light-client";

// Typed to match the real generated declarations.
interface WasmLightState {
  applyBlock(wire: Uint8Array, expected_proposer?: string | null): unknown;
  stateRoot(): string;
  tip(): unknown;
  balanceOf(addr: string, now: bigint): string;
  nonceOf(addr: string): bigint;
  humanStatus(addr: string): number;
  serialize(): Uint8Array;
  free(): void;
}

interface WasmLightStateConstructor {
  new (
    chain_id: bigint,
    genesis_hash: string,
    genesis_state_root: string,
    genesis_time: bigint,
  ): WasmLightState;
  deserialize(bytes: Uint8Array): WasmLightState;
}

interface WasmModule {
  default: (url?: string | URL) => Promise<unknown>;
  LightState: WasmLightStateConstructor;
}

let wasmModule: WasmModule | null = null;
let initPromise: Promise<void> | null = null;

/**
 * Initialise the WASM module. Safe to call multiple times — subsequent calls return the same promise.
 */
export async function initWasm(wasmUrl?: string): Promise<void> {
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const mod = await import(
      /* @vite-ignore */
      "../../../packages/light-client/wasm/ubi2_runtime_wasm.js"
    ) as WasmModule;

    const resolvedUrl = wasmUrl ?? new URL(
      "../../../packages/light-client/wasm/ubi2_runtime_wasm_bg.wasm",
      import.meta.url,
    ).href;

    await mod.default(resolvedUrl);
    wasmModule = mod;
  })();

  return initPromise;
}

/**
 * Adapter: wraps a WasmLightState so it satisfies ILightState (number-typed chain_id/genesis_time).
 */
class WasmLightStateAdapter implements ILightState {
  constructor(private inner: WasmLightState) {}

  applyBlock(wire: Uint8Array, expectedProposer?: string): BlockOutcome {
    const outcome = this.inner.applyBlock(wire, expectedProposer ?? null) as BlockOutcome;
    return outcome;
  }

  stateRoot(): string {
    return this.inner.stateRoot();
  }

  tip(): TipInfo {
    return this.inner.tip() as TipInfo;
  }

  balanceOf(addr: string, now: bigint): string {
    return this.inner.balanceOf(addr, now);
  }

  nonceOf(addr: string): number {
    return Number(this.inner.nonceOf(addr));
  }

  humanStatus(addr: string): number {
    return this.inner.humanStatus(addr);
  }

  serialize(): Uint8Array {
    return this.inner.serialize();
  }
}

/**
 * Build a LightStateFactory backed by the real WASM kernel.
 * Must be called after `await initWasm()`.
 */
export function wasmLightStateFactory(): LightStateFactory {
  return (
    chainId: number,
    genesisHash: string,
    genesisStateRoot: string,
    genesisTime: number,
  ): ILightState => {
    if (!wasmModule) throw new Error("WASM not initialised — call initWasm() first");
    const inner = new wasmModule.LightState(
      BigInt(chainId),
      genesisHash,
      genesisStateRoot,
      BigInt(genesisTime),
    );
    return new WasmLightStateAdapter(inner);
  };
}

export function isWasmReady(): boolean {
  return wasmModule !== null;
}

export type { ILightState, LightStateFactory, BlockOutcome, TipInfo };
