/* tslint:disable */
/* eslint-disable */

/**
 * The verified light-node state the TypeScript client holds: a `LightCore` (verified `MemState` +
 * tip). One handle per chain; the client constructs it from the gateway-advertised genesis, then
 * `applyBlock`s every synced/streamed block before its UI tip advances.
 */
export class LightState {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decode + re-execute + root-verify a canonical `WireBlock` (the bytes the gateway served, the
     * SAME `ubi2/sync/1` payload a server follower verifies). On success the verified tip advances
     * and the accepted block's `{number,hash,stateRoot,timestamp}` is returned; on ANY failure a
     * JS error is thrown and the verified state is unchanged (LC-2/LC-5/AC-LC2 — a forged block is
     * caught by re-execution, the UI shows a red verification error, never a wrong balance).
     *
     * `expected_proposer` (optional `0x`-hex 20-byte address) pins the scheduled proposer.
     */
    applyBlock(wire: Uint8Array, expected_proposer?: string | null): any;
    /**
     * The streaming balance of `addr` at unix-second `now`, as a **decimal string** of base units
     * (I2, §2.2). NEVER a JS `number` — an 18-decimal UBI balance overflows `2^53` in seconds. The
     * caller's `now` projects the stream forward for display; the value is the exact integer
     * `Account::balance(now)` the chain commits, re-anchored on every verified block.
     */
    balanceOf(addr: string, now: bigint): string;
    /**
     * Restore a verified state + tip from a [`LightState::serialize`] snapshot. The client MUST
     * re-verify `stateRoot()` against the stored tip on load and discard + re-sync on mismatch
     * (spec §3.3 — a poisoned IndexedDB entry is not trusted).
     */
    static deserialize(bytes: Uint8Array): LightState;
    /**
     * Construct the verified state from a **pinned, gateway-independent genesis anchor** (spec 07
     * §3.4 — the `ln-trust-1/2/3` fix). The light client calls THIS (not the empty-state `new`) for a
     * real seeded chain:
     *   * `genesis_snapshot` is the seeded genesis state the gateway served (untrusted bytes).
     *   * `pinned_state_root` is the app's HARD-CODED genesis `state_root` constant. The kernel
     *     re-derives the root from the snapshot LOCALLY and throws unless it equals this — so a lying
     *     gateway is caught and the all-zeros default is never silently accepted.
     *   * `validator_set` is a JSON array of `0x`-hex 20-byte proposer addresses; it is pinned and
     *     enforced on EVERY block (always-on proposer authority — no None-skip).
     * On success the verified tip is height 0 over the verified seeded state.
     */
    static genesisImport(chain_id: bigint, genesis_hash: string, pinned_state_root: string, genesis_time: bigint, genesis_snapshot: Uint8Array, validator_set: string[]): LightState;
    /**
     * The PoH status tag of `addr` (`0`=Unverified, `1`=Pending, `2`=Verified, `3`=Challenged,
     * `4`=Revoked).
     */
    humanStatus(addr: string): number;
    /**
     * Construct the empty verified state at the genesis the gateway advertised (spec §2.2). All
     * args cross as JS-safe types: `chain_id`/`genesis_time` as numbers (devnet-safe), the genesis
     * block hash + state root as `0x` hex strings.
     */
    constructor(chain_id: bigint, genesis_hash: string, genesis_state_root: string, genesis_time: bigint);
    /**
     * The current nonce of `addr` (0 if unknown) — for composing the next tx.
     */
    nonceOf(addr: string): bigint;
    /**
     * Canonical snapshot of the verified state + tip, for IndexedDB persistence (spec §3.3). The
     * bytes round-trip through [`LightState::deserialize`] to a byte-identical state (same root).
     */
    serialize(): Uint8Array;
    /**
     * Re-pin the PoA validator set after a snapshot `deserialize` (`ln-trust-1`), so proposer
     * authority is enforced on the next block even on a resumed session. `validator_set` is a JSON
     * array of `0x`-hex 20-byte addresses.
     */
    setValidatorSet(validator_set: string[]): void;
    /**
     * The 32-byte `state_root` over the current verified state, as a `0x` hex string — the SAME
     * commitment consensus uses (`ubi2_runtime::state_root`).
     */
    stateRoot(): string;
    /**
     * The verified tip `{ number, hash, stateRoot, timestamp }` as a JS object.
     */
    tip(): any;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_lightstate_free: (a: number, b: number) => void;
    readonly lightstate_applyBlock: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly lightstate_balanceOf: (a: number, b: number, c: number, d: bigint) => [number, number, number, number];
    readonly lightstate_deserialize: (a: number, b: number) => [number, number, number];
    readonly lightstate_genesisImport: (a: bigint, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly lightstate_humanStatus: (a: number, b: number, c: number) => [number, number, number];
    readonly lightstate_new: (a: bigint, b: number, c: number, d: number, e: number, f: bigint) => [number, number, number];
    readonly lightstate_nonceOf: (a: number, b: number, c: number) => [bigint, number, number];
    readonly lightstate_serialize: (a: number) => [number, number];
    readonly lightstate_setValidatorSet: (a: number, b: number, c: number) => [number, number];
    readonly lightstate_stateRoot: (a: number) => [number, number];
    readonly lightstate_tip: (a: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
