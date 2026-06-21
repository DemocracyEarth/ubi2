/** Devnet wallet configuration. RPC URL is overridable via NEXT_PUBLIC_RPC_URL. */

import { DEVNET_CHAIN_ID } from "@ubi2/sdk";

export const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL ?? "http://127.0.0.1:8545";

/** Pre-verified genesis dev account (well-known devnet key — not a secret). */
export const DEV_ACCOUNT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

export const NETWORK = {
  chainName: "ubi2 devnet",
  chainIdHex: `0x${DEVNET_CHAIN_ID.toString(16)}`,
  chainIdDec: DEVNET_CHAIN_ID, // 21826
  rpcUrl: RPC_URL,
  symbol: "UBI",
  decimals: 18,
} as const;
