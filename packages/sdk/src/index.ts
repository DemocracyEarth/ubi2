/**
 * @ubi2/sdk — minimal typed JSON-RPC client for the ubi2 chain (M0 skeleton).
 *
 * Targets the EVM-compatible RPC defined in `docs/specs/01-evm-rpc-and-wallet.md`. The
 * `interface-engineer` extends this with EVM provider glue (viem/ethers-compatible) in task M1-T5.
 * Uses the global `fetch` (Node ≥ 18, browsers).
 */

export const UBI_DECIMALS = 18n;
export const UBI = 10n ** UBI_DECIMALS;

export interface Ubi2ClientOptions {
  /** JSON-RPC endpoint, e.g. http://127.0.0.1:8545 */
  url: string;
}

let nextId = 1;

export class Ubi2Client {
  constructor(private readonly opts: Ubi2ClientOptions) {}

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

  async chainId(): Promise<number> {
    return parseInt(await this.call<string>("eth_chainId"), 16);
  }

  async blockNumber(): Promise<number> {
    return parseInt(await this.call<string>("eth_blockNumber"), 16);
  }

  /** Live streaming balance in base units (wei-style). */
  async getBalance(address: string, block: string = "latest"): Promise<bigint> {
    return BigInt(await this.call<string>("eth_getBalance", [address, block]));
  }
}

/** Format base units as a human UBI string. */
export function formatUbi(baseUnits: bigint): string {
  const whole = baseUnits / UBI;
  const frac = (baseUnits % UBI).toString().padStart(Number(UBI_DECIMALS), "0").slice(0, 4);
  return `${whole}.${frac} UBI`;
}
