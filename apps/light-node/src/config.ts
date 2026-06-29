/**
 * Light-node configuration.
 *
 * Override via URL hash:  #gateway=ws://127.0.0.1:8546&chainId=21826&address=0x...
 * The hash approach keeps config in the URL without a server-round-trip, and works
 * as a static app deployed to IPFS.
 */

export interface LightNodeConfig {
  /** ws:// or wss:// gateway URL */
  gatewayUrl: string;
  /** Expected chain id (21826 = 0x5542 for ubi2 devnet) */
  chainId: number;
  /** Optional expected genesis hash (0x-hex 32 bytes) */
  genesisHash?: string;
  /** Optional expected genesis state root (0x-hex 32 bytes) */
  genesisStateRoot?: string;
  /** Optional genesis unix time (seconds) */
  genesisTime?: number;
  /** Pre-filled address to watch */
  watchAddress?: string;
}

const DEVNET_CHAIN_ID = 0x5542; // 21826

function parseHash(): Partial<LightNodeConfig> {
  if (typeof window === "undefined") return {};
  const hash = window.location.hash.slice(1);
  if (!hash) return {};
  const params = new URLSearchParams(hash);
  const result: Partial<LightNodeConfig> = {};
  const gw = params.get("gateway");
  if (gw) result.gatewayUrl = gw;
  const cid = params.get("chainId");
  if (cid) result.chainId = parseInt(cid, 10);
  const gh = params.get("genesisHash");
  if (gh) result.genesisHash = gh;
  const gr = params.get("genesisStateRoot");
  if (gr) result.genesisStateRoot = gr;
  const gt = params.get("genesisTime");
  if (gt) result.genesisTime = parseInt(gt, 10);
  const addr = params.get("address");
  if (addr) result.watchAddress = addr;
  return result;
}

export function getConfig(): LightNodeConfig {
  const overrides = parseHash();
  return {
    gatewayUrl: overrides.gatewayUrl ?? "ws://127.0.0.1:8546",
    chainId: overrides.chainId ?? DEVNET_CHAIN_ID,
    genesisHash: overrides.genesisHash,
    genesisStateRoot: overrides.genesisStateRoot,
    genesisTime: overrides.genesisTime,
    watchAddress: overrides.watchAddress ?? "",
  };
}

/** Persist the watch address in localStorage so it survives a reload. */
export function saveWatchAddress(addr: string): void {
  try { localStorage.setItem("ubi2:watchAddress", addr); } catch (_) { /* ignore */ }
}

export function loadWatchAddress(): string {
  try { return localStorage.getItem("ubi2:watchAddress") ?? ""; } catch (_) { return ""; }
}
