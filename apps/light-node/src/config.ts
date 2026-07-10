/**
 * Light-node configuration.
 *
 * ## The PINNED, gateway-independent genesis anchor (spec 07 §3.4 — `ln-trust-1/2/3`)
 * The trust model is "trust no server, re-execute from genesis". For that to hold, the app must carry
 * a HARD-CODED, verifiable genesis anchor — the genesis hash, the SEEDED genesis state_root, and the
 * authorized PoA proposer/validator set — DERIVED from the actual devnet genesis (see
 * `crates/node/src/main.rs` genesis seeding + the `seal_genesis` anchor). The light client REJECTS any
 * gateway whose advertised genesis hash/root/proposer != these constants; it never adopts the gateway's.
 * A lying gateway serving a self-consistent chain from ITS OWN genesis is therefore caught, not trusted.
 *
 * These constants are pinned to the canonical devnet genesis time `1700000000` (the value the multi-node
 * devnet, `scripts/devnet-multi.sh`, and the integration tests all use). A node started with a different
 * `UBI2_GENESIS_TIME` (or the wall-clock default) is a DIFFERENT network and is correctly rejected.
 *
 * The gateway URL + watch address may still be overridden via the URL hash; the ANCHOR constants are NOT
 * overridable from the URL (overriding the pinned anchor would defeat the trust model). A genesisTime
 * hash override is accepted only for local dev against a re-pinned anchor.
 */

export interface LightNodeConfig {
  /** ws:// or wss:// gateway URL */
  gatewayUrl: string;
  /** Pinned chain id (21826 = 0x5542 for ubi2 devnet) */
  chainId: number;
  /** PINNED genesis hash (0x-hex 32 bytes) — REQUIRED; a mismatch ⇒ WrongNetwork. */
  genesisHash: string;
  /** PINNED seeded genesis state root (0x-hex 32 bytes) — REQUIRED; verified locally vs the snapshot. */
  genesisStateRoot: string;
  /** Pinned genesis unix time (seconds). */
  genesisTime: number;
  /** PINNED PoA validator/proposer set (0x-hex 20-byte addresses) — enforced on every block. */
  validatorSet: string[];
  /** Pre-filled address to watch */
  watchAddress?: string;
}

const DEVNET_CHAIN_ID = 0x5542; // 21826

// ---------------------------------------------------------------------------------------------
// PINNED devnet genesis anchor (genesis_time = 1700000000). Derived from the actual node genesis
// seeding (dev account + verified human + the 3 devnet jurors + CSCA + governance) — see
// `crates/node/tests/sync_gateway.rs::genesis_anchor_pinned_and_reproduced` for the matching anchor.
// To re-pin (e.g. if the genesis seeds change), recompute via the node's sealed `genesis_anchor()`.
// ---------------------------------------------------------------------------------------------
const PINNED_GENESIS_TIME = 1_700_000_000;
const PINNED_GENESIS_HASH =
  "0xbc53563fa41f719abe0358f106b067e31915a6ed68d0656ba7443a36f01224e3";
const PINNED_GENESIS_STATE_ROOT =
  "0x2ceab410e36255e646826ae52093e4ed438700e4654104b2f79ae74a4f03fb98";
/** The authorized PoA proposer — Anvil acct #2 (the multi-node devnet's designated proposer). */
const PINNED_VALIDATOR_SET = ["0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"];

function parseHash(): Partial<Pick<LightNodeConfig, "gatewayUrl" | "watchAddress">> {
  if (typeof window === "undefined") return {};
  const hash = window.location.hash.slice(1);
  if (!hash) return {};
  const params = new URLSearchParams(hash);
  const result: Partial<Pick<LightNodeConfig, "gatewayUrl" | "watchAddress">> = {};
  const gw = params.get("gateway");
  if (gw) result.gatewayUrl = gw;
  const addr = params.get("address");
  if (addr) result.watchAddress = addr;
  // NOTE: the genesis ANCHOR (hash/root/proposer) is intentionally NOT overridable from the URL — a
  // gateway-supplied or URL-supplied anchor would defeat the "trust no server" guarantee (ln-trust-1).
  return result;
}

export function getConfig(): LightNodeConfig {
  const overrides = parseHash();
  return {
    gatewayUrl: overrides.gatewayUrl ?? "ws://127.0.0.1:8546",
    chainId: DEVNET_CHAIN_ID,
    genesisHash: PINNED_GENESIS_HASH,
    genesisStateRoot: PINNED_GENESIS_STATE_ROOT,
    genesisTime: PINNED_GENESIS_TIME,
    validatorSet: PINNED_VALIDATOR_SET,
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
