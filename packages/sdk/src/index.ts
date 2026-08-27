/**
 * @ubi2/sdk — typed JSON-RPC client for the ubi2 chain.
 *
 * Targets the EVM-compatible RPC defined in `docs/specs/01-evm-rpc-and-wallet.md` and the M2
 * streaming surface in `docs/specs/02-streaming.md`. Provides a thin typed client over the
 * documented `eth_*` methods, a client-side streaming-balance helper so UIs can tick a balance
 * every animation frame without polling the node on every frame, and the M2 stream/NFT helpers
 * (calldata encoders, `ubi_getStreams`, on-chain NFT card decoding, and a send helper that works
 * with either an injected provider or a local private key). Uses the global `fetch` (Node ≥ 18,
 * browsers).
 */

export * from "./streaming";
export * from "./humanity";
export * from "./contracts";
export * from "./explorer";
export * from "./oracle";
export * from "./passport";
export * from "./predicate";
export * from "./credential-vault";
export * from "./zk-identity-policy";
export * from "./zk-identity-status-manifest";
export * from "./zk-identity-packed-status";
export * from "./zk-identity-status-snapshot";
export * from "./zk-identity-status-ingestion";
export * from "./zk-identity-encoding";
export * from "./zk-self-issuance";
export * from "./zk-holder-credential";
export * from "./zk-holder-reference-handoff";
export * from "./zk-production-profile";
export * from "./zk-sanctions-ceremony";
export * from "./zk-holder-reference-prover-worker";
export * from "./zk-holder-reference-browser-runtime";
export * from "./zk-holder-profile-prover-worker";
export * from "./zk-holder-profile-browser-runtime";
export * from "./zk-holder-production-vault";
export * from "./zk-holder-private-status-refresh";
export * from "./zk-holder-private-status-refresh-browser-runtime";

export const UBI_DECIMALS = 18n;
export const UBI = 10n ** UBI_DECIMALS;

/** Emission period: a verified account accrues 1 UBI per hour (spec invariant I2). */
export const EMISSION_PERIOD_SECS = 3600n;

/**
 * Streaming rate in base units per second: `10**18 / 3600`.
 * Kept as a {num, den} rational so callers can interpolate with exact integer math
 * (no floats in the balance path, matching the on-chain model).
 */
export const EMISSION_RATE = { num: UBI, den: EMISSION_PERIOD_SECS } as const;

/** The well-known devnet chain id (`0x5542` / 21826). */
export const DEVNET_CHAIN_ID = 0x5542;

export interface Ubi2ClientOptions {
  /** JSON-RPC endpoint, e.g. http://127.0.0.1:8545 */
  url: string;
}

/** Standard EVM block header as returned by `eth_getBlockByNumber` (hex-encoded fields). */
export interface Block {
  number: string;
  hash: string;
  parentHash: string;
  timestamp: string;
  gasLimit: string;
  gasUsed: string;
  miner: string;
  size: string;
  transactions: string[] | unknown[];
}

let nextId = 1;

export class Ubi2Client {
  constructor(private readonly opts: Ubi2ClientOptions) {}

  /** The configured JSON-RPC endpoint. */
  get url(): string {
    return this.opts.url;
  }

  /** Low-level JSON-RPC call. */
  async call<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    const res = await fetch(this.opts.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
    });
    const json = (await res.json()) as { result?: T; error?: { message: string } };
    if (json.error) throw new Error(`${method}: ${json.error.message}`);
    return json.result as T;
  }

  /** Chain id as a number (decoded from the hex `eth_chainId` result). */
  async chainId(): Promise<number> {
    return parseInt(await this.call<string>("eth_chainId"), 16);
  }

  /** Latest block height as a number. */
  async blockNumber(): Promise<number> {
    return parseInt(await this.call<string>("eth_blockNumber"), 16);
  }

  /** Live streaming balance in base units (wei-style). */
  async getBalance(address: string, block: string = "latest"): Promise<bigint> {
    return BigInt(await this.call<string>("eth_getBalance", [address, block]));
  }

  /** Account nonce / transaction count as a number. */
  async getTransactionCount(address: string, block: string = "latest"): Promise<number> {
    return parseInt(await this.call<string>("eth_getTransactionCount", [address, block]), 16);
  }

  /**
   * Fetch a block header. `n` may be a block number or a tag (`"latest"`, `"earliest"`,
   * `"pending"`). Pass `fullTx` to include full transaction objects instead of hashes.
   */
  async getBlockByNumber(n: number | string, fullTx = false): Promise<Block | null> {
    const tag = typeof n === "number" ? `0x${n.toString(16)}` : n;
    return this.call<Block | null>("eth_getBlockByNumber", [tag, fullTx]);
  }

  /**
   * Snapshot a streaming balance at the moment of an RPC read so the UI can interpolate forward.
   * Captures the base balance plus the wall-clock instant it was observed.
   */
  async sampleBalance(address: string, block: string = "latest"): Promise<BalanceSample> {
    const base = await this.getBalance(address, block);
    return { base, atMs: Date.now() };
  }
}

/** A balance reading anchored to the wall-clock time it was observed. */
export interface BalanceSample {
  /** Balance in base units returned by the node. */
  base: bigint;
  /** `Date.now()` at the moment of the read. */
  atMs: number;
}

/**
 * Interpolate a streaming balance forward from a sample using exact integer math.
 *
 * Given a base balance observed at `sample.atMs` and the known emission rate (1 UBI/hour), this
 * projects the balance at wall-clock time `nowMs`. Drive it from `requestAnimationFrame` so the
 * displayed number climbs smoothly between RPC polls without hammering the node.
 *
 * Note: this is a *display* extrapolation. Each fresh `sampleBalance` re-anchors it to ground
 * truth, so any clock drift is corrected on the next poll rather than accumulating.
 */
export function projectBalance(
  sample: BalanceSample,
  nowMs: number = Date.now(),
  rate: { num: bigint; den: bigint } = EMISSION_RATE,
): bigint {
  const elapsedMs = nowMs - sample.atMs;
  if (elapsedMs <= 0) return sample.base;
  // base + rate.num * elapsedMs / (rate.den * 1000), truncating like the on-chain model.
  const accrued = (rate.num * BigInt(Math.floor(elapsedMs))) / (rate.den * 1000n);
  return sample.base + accrued;
}

/**
 * Format base units as a human UBI string with `frac` fractional digits (default 4).
 * Truncates (does not round) so the displayed value never overshoots the real balance.
 */
export function formatUbi(baseUnits: bigint, frac = 4): string {
  const neg = baseUnits < 0n;
  const abs = neg ? -baseUnits : baseUnits;
  const whole = abs / UBI;
  const fracStr = (abs % UBI).toString().padStart(Number(UBI_DECIMALS), "0").slice(0, frac);
  return `${neg ? "-" : ""}${whole}.${fracStr} UBI`;
}
