/**
 * proofofhumanity.org configuration.
 *
 * Two audiences share this file:
 *   - the CLIENT (page.tsx, self-client.ts) reads `CHAINS`, `SELF_SCOPE`, `SELF_ENDPOINT`,
 *     `SELF_ENDPOINT_TYPE` — all safe to ship to the browser (`NEXT_PUBLIC_*` or constants);
 *   - the SERVER (api/self-verify/route.ts) additionally reads `ISSUER_PRIVATE_KEY` and
 *     `SELF_MOCK_PASSPORT`. `ISSUER_PRIVATE_KEY` has NO `NEXT_PUBLIC_` prefix, so Next.js strips
 *     it from the client bundle — it never reaches the browser.
 *
 * The issuer key is the one whose address the deployed `ProofOfHumanity.issuer` must equal.
 * In dev it defaults to the well-known Anvil account #1 key (NOT a secret) so the app runs with
 * zero setup against a locally-deployed contract; set `ISSUER_PRIVATE_KEY` in production.
 */

import type { Address, Hex } from "viem";

export interface ChainConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  /** The ProofOfHumanity deployment on this chain. */
  pohAddress: Address;
  /** Optional block-explorer base for "view token" links. */
  explorer?: string;
}

/**
 * Per-chain ProofOfHumanity deployments the mint UI offers. Addresses are overridable via env so
 * a real deployment can be wired without a rebuild. The zero-address placeholders mark chains that
 * are configured but not yet deployed — the UI disables minting on those.
 *
 * NOTE: the same bytecode is deployed per chain, but each has its own EIP-712 domain
 * (`chainId` + `verifyingContract`), so the relay signs a distinct voucher per chain.
 */
export const CHAINS: ChainConfig[] = [
  {
    chainId: Number(process.env.NEXT_PUBLIC_LOCAL_CHAIN_ID ?? 31337),
    name: process.env.NEXT_PUBLIC_LOCAL_CHAIN_NAME ?? "Anvil (local)",
    rpcUrl: process.env.NEXT_PUBLIC_LOCAL_RPC_URL ?? "http://127.0.0.1:8545",
    pohAddress: (process.env.NEXT_PUBLIC_LOCAL_POH ?? "0x0000000000000000000000000000000000000000") as Address,
  },
  {
    chainId: 8453,
    name: "Base",
    rpcUrl: process.env.NEXT_PUBLIC_BASE_RPC_URL ?? "https://mainnet.base.org",
    pohAddress: (process.env.NEXT_PUBLIC_BASE_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://basescan.org",
  },
  {
    chainId: 42220,
    name: "Celo",
    rpcUrl: process.env.NEXT_PUBLIC_CELO_RPC_URL ?? "https://forno.celo.org",
    pohAddress: (process.env.NEXT_PUBLIC_CELO_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://celoscan.io",
  },
  {
    chainId: 10,
    name: "Optimism",
    rpcUrl: process.env.NEXT_PUBLIC_OP_RPC_URL ?? "https://mainnet.optimism.io",
    pohAddress: (process.env.NEXT_PUBLIC_OP_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://optimistic.etherscan.io",
  },
];

/** A chain is mintable only once its ProofOfHumanity address is set (non-zero). */
export function isDeployed(chain: ChainConfig): boolean {
  return /^0x0{40}$/i.test(chain.pohAddress) === false;
}

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

/*//////////////////////////////////////////////////////////////
                          SELF (self.xyz)
//////////////////////////////////////////////////////////////*/

/** The canonical scope — MUST match on both the SelfAppBuilder and the SelfBackendVerifier. */
export const SELF_SCOPE = "proofofhumanity";

/** The app name shown in the Self mobile app. */
export const SELF_APP_NAME = "Proof of Humanity";

/**
 * The public HTTPS URL of THIS app's `/api/self-verify` route, as the Self mobile app sees it.
 * `SelfAppBuilder` rejects `localhost`/`127.0.0.1` (the proof is generated on a phone that cannot
 * reach your laptop), so a real end-to-end run needs a publicly reachable URL — a tunnel
 * (ngrok/cloudflared) in dev, or the deployed origin in prod. Empty → the live QR panel stays
 * disabled with an honest message.
 */
export const SELF_ENDPOINT = process.env.NEXT_PUBLIC_SELF_ENDPOINT ?? "";

/**
 * "staging" (default) targets Self's STAGING/mock environment — accepts Self's test passports and
 * the Celo *testnet* identity hub, for de-risking the plumbing before a real passport. "production"
 * targets the real passport + Celo mainnet hub. This flips BOTH the frontend `endpointType` and
 * the backend `mockPassport` flag in lockstep (mixing them makes the verifier reject).
 */
export const SELF_ENV = (process.env.NEXT_PUBLIC_SELF_ENV ?? "staging") as "staging" | "production";
export const SELF_ENDPOINT_TYPE: "staging_https" | "https" = SELF_ENV === "production" ? "https" : "staging_https";

/** Backend: `mockPassport` for `SelfBackendVerifier` — true in staging, false in production. */
export const SELF_MOCK_PASSPORT = SELF_ENV !== "production";

/*//////////////////////////////////////////////////////////////
                       ISSUER (server-only)
//////////////////////////////////////////////////////////////*/

/**
 * The voucher-signing key. Its address MUST equal `ProofOfHumanity.issuer` on every chain the UI
 * offers. Defaults to Anvil account #1's well-known key (NOT a secret) for local dev; set the env
 * var in production. Read only in server code (no NEXT_PUBLIC_ prefix → stripped from the client).
 */
export const ISSUER_PRIVATE_KEY = (process.env.ISSUER_PRIVATE_KEY ??
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d") as Hex;

/** Voucher deadline / credential lifetime: now + 365 days (uint64 seconds). */
export const VOUCHER_TTL_SECONDS = 365n * 24n * 60n * 60n;
