/** Devnet wallet configuration. RPC URL is overridable via NEXT_PUBLIC_RPC_URL. */

import { DEVNET_CHAIN_ID } from "@ubi2/sdk";

export const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL ?? "http://127.0.0.1:8545";

/** Pre-verified genesis dev account (well-known devnet key — not a secret). */
export const DEV_ACCOUNT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/**
 * Well-known devnet dev private key (public Anvil/Hardhat account #0 — NOT a secret).
 * Used only as the local-demo signer when no injected wallet is connected.
 */
export const DEV_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

/**
 * The block explorer URL base for this wallet app.
 * Used in wallet_addEthereumChain so MetaMask shows "View on explorer" links.
 * Defaults to the app's own origin at runtime.
 */
export function getExplorerUrl(): string {
  if (typeof window !== "undefined") {
    return window.location.origin;
  }
  return "http://127.0.0.1:3000";
}

export const NETWORK = {
  chainName: "ubi2 devnet",
  chainIdHex: `0x${DEVNET_CHAIN_ID.toString(16)}`,
  chainIdDec: DEVNET_CHAIN_ID, // 21826
  rpcUrl: RPC_URL,
  symbol: "UBI",
  decimals: 18,
} as const;

/**
 * M6 Stage C1 (spec 06b §5.1) — the public URL of THIS app's `/api/self-verify` relay route, as
 * seen by the Self mobile app. `SelfAppBuilder` hard-rejects `localhost`/`127.0.0.1` endpoints
 * (the Self app runs on a phone, not this machine), so a real end-to-end run requires a publicly
 * reachable URL here — a tunnel (ngrok/cloudflared) during dev, or the deployed wallet's own
 * origin in production. Leave unset to keep the live-QR panel disabled with an honest message
 * (the paste/upload + dev-fixture paths keep working regardless).
 *
 * Example (dev): `NEXT_PUBLIC_SELF_ENDPOINT=https://abcd1234.ngrok-free.app/api/self-verify pnpm dev`
 */
export const SELF_ENDPOINT = process.env.NEXT_PUBLIC_SELF_ENDPOINT ?? "";

/** The canonical ubi2 Self scope seed (spec 06b §3) — one network-wide scope, never per-context. */
export const UBI2_SELF_SCOPE_SEED = "ubi2-poh";
