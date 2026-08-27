/* tslint:disable */
/* eslint-disable */

/**
 * Browser-local commitment entry point. The JSON source is consumed in WASM
 * memory and the returned descriptor contains no private fields.
 */
export function buildHolderCredentialCommitment(source: string): string;

/**
 * Derive the private depth-24 path wholly inside WASM/Worker memory.
 */
export function buildPackedStatusPath(source: string, status_id: number): string;

export function generatePackedStatusProvingKey(): Uint8Array;

export function generateRegistryProvingKey(depth: number): Uint8Array;

/**
 * Reference-only 18-signal proof entry point. The deterministic fixture,
 * toxic-waste setup, proof and verification key stay inside WASM/Worker memory.
 */
export function proveDynamicStatusReference(): string;

export function provePackedStatus(proving_key: Uint8Array): string;

export function proveRegistryDepth(depth: number, proving_key: Uint8Array): string;

/**
 * Profile-specific holder entry point. Only the exact synthetic credential is
 * accepted until production ceremony artifacts and a production vault schema
 * have passed admission.
 */
export function proveSyntheticHolderProfile(private_credential_json: string): string;

/**
 * Validate a complete canonical sparse status snapshot and its Poseidon root.
 */
export function validatePackedStatusSnapshot(source: string): void;

/**
 * ADR-0014 payload verifier. Errors remain inside the disposable Worker and
 * are collapsed to the bounded public failure enum by the TypeScript boundary.
 */
export function verifyProductionVaultPayload(source: string): void;

export function wasmLinearMemoryBytes(): number;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly buildHolderCredentialCommitment: (a: number, b: number) => [number, number, number, number];
    readonly buildPackedStatusPath: (a: number, b: number, c: number) => [number, number, number, number];
    readonly generatePackedStatusProvingKey: () => [number, number, number, number];
    readonly generateRegistryProvingKey: (a: number) => [number, number, number, number];
    readonly proveDynamicStatusReference: () => [number, number, number, number];
    readonly provePackedStatus: (a: number, b: number) => [number, number, number, number];
    readonly proveRegistryDepth: (a: number, b: number, c: number) => [number, number, number, number];
    readonly proveSyntheticHolderProfile: (a: number, b: number) => [number, number, number, number];
    readonly validatePackedStatusSnapshot: (a: number, b: number) => [number, number];
    readonly verifyProductionVaultPayload: (a: number, b: number) => [number, number];
    readonly wasmLinearMemoryBytes: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
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
