/**
 * proofofhumanity.org configuration.
 *
 * Two audiences share this file:
 *   - the CLIENT (page.tsx, self-client.ts) reads `CHAINS`, `SELF_SCOPE`, `SELF_ENDPOINT`,
 *     `SELF_ENDPOINT_TYPE` — all safe to ship to the browser (`NEXT_PUBLIC_*` or constants);
 *   - the SERVER additionally reads `SELF_MOCK_PASSPORT`. Signing keys live in
 *     `server-config.ts`, guarded by `server-only`, and can never enter a client bundle.
 *
 * The issuer address on every deployed ProofOfHumanity and PredicateVerifier must match the
 * server-side signer. The API checks that binding against the target chain before attesting.
 */

import type { Address } from "viem";

export interface ChainConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  /** The ProofOfHumanity deployment on this chain. */
  pohAddress: Address;
  /** The PredicateVerifier deployment on this chain. */
  predicateAddress: Address;
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
    predicateAddress: (process.env.NEXT_PUBLIC_LOCAL_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
  },
  {
    chainId: 11155111,
    name: "Ethereum Sepolia",
    rpcUrl: process.env.NEXT_PUBLIC_ETHEREUM_SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com",
    pohAddress: (process.env.NEXT_PUBLIC_ETHEREUM_SEPOLIA_POH ??
      "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_ETHEREUM_SEPOLIA_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://sepolia.etherscan.io",
  },
  {
    chainId: 84532,
    name: "Base Sepolia",
    rpcUrl: process.env.NEXT_PUBLIC_BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org",
    pohAddress: (process.env.NEXT_PUBLIC_BASE_SEPOLIA_POH ??
      "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_BASE_SEPOLIA_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://sepolia.basescan.org",
  },
  {
    chainId: 11142220,
    name: "Celo Sepolia",
    rpcUrl: process.env.NEXT_PUBLIC_CELO_SEPOLIA_RPC_URL ?? "https://forno.celo-sepolia.celo-testnet.org",
    pohAddress: (process.env.NEXT_PUBLIC_CELO_SEPOLIA_POH ??
      "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_CELO_SEPOLIA_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://celo-sepolia.blockscout.com",
  },
  {
    chainId: 4801,
    name: "World Chain Sepolia",
    rpcUrl: process.env.NEXT_PUBLIC_WORLD_SEPOLIA_RPC_URL ?? "https://worldchain-sepolia.g.alchemy.com/public",
    pohAddress: (process.env.NEXT_PUBLIC_WORLD_SEPOLIA_POH ??
      "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_WORLD_SEPOLIA_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://sepolia.worldscan.org",
  },
  {
    chainId: 46630,
    name: "Robinhood Chain Testnet",
    rpcUrl: process.env.NEXT_PUBLIC_ROBINHOOD_TESTNET_RPC_URL ?? "https://rpc.testnet.chain.robinhood.com",
    pohAddress: (process.env.NEXT_PUBLIC_ROBINHOOD_TESTNET_POH ??
      "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_ROBINHOOD_TESTNET_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://explorer.testnet.chain.robinhood.com",
  },
  {
    chainId: 1,
    name: "Ethereum",
    rpcUrl: process.env.NEXT_PUBLIC_ETHEREUM_RPC_URL ?? "https://ethereum-rpc.publicnode.com",
    pohAddress: (process.env.NEXT_PUBLIC_ETHEREUM_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_ETHEREUM_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://etherscan.io",
  },
  {
    chainId: 8453,
    name: "Base",
    rpcUrl: process.env.NEXT_PUBLIC_BASE_RPC_URL ?? "https://mainnet.base.org",
    pohAddress: (process.env.NEXT_PUBLIC_BASE_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_BASE_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://basescan.org",
  },
  {
    chainId: 42220,
    name: "Celo",
    rpcUrl: process.env.NEXT_PUBLIC_CELO_RPC_URL ?? "https://forno.celo.org",
    pohAddress: (process.env.NEXT_PUBLIC_CELO_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_CELO_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://celoscan.io",
  },
  {
    chainId: 10,
    name: "Optimism",
    rpcUrl: process.env.NEXT_PUBLIC_OP_RPC_URL ?? "https://mainnet.optimism.io",
    pohAddress: (process.env.NEXT_PUBLIC_OP_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_OP_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://optimistic.etherscan.io",
  },
  {
    chainId: 480,
    name: "World Chain",
    rpcUrl: process.env.NEXT_PUBLIC_WORLD_RPC_URL ?? "https://worldchain-mainnet.g.alchemy.com/public",
    pohAddress: (process.env.NEXT_PUBLIC_WORLD_POH ?? "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_WORLD_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://worldscan.org",
  },
  {
    chainId: 4663,
    name: "Robinhood Chain",
    rpcUrl: process.env.NEXT_PUBLIC_ROBINHOOD_RPC_URL ?? "https://rpc.mainnet.chain.robinhood.com",
    pohAddress: (process.env.NEXT_PUBLIC_ROBINHOOD_POH ??
      "0x0000000000000000000000000000000000000000") as Address,
    predicateAddress: (process.env.NEXT_PUBLIC_ROBINHOOD_PREDICATE ??
      "0x0000000000000000000000000000000000000000") as Address,
    explorer: "https://robinhoodchain.blockscout.com",
  },
];

/** A chain is mintable only once its ProofOfHumanity address is set (non-zero). */
export function isDeployed(chain: ChainConfig): boolean {
  return /^0x0{40}$/i.test(chain.pohAddress) === false;
}

/** A predicate target is usable only when both halves of the trust binding are deployed. */
export function isPredicateDeployed(chain: ChainConfig): boolean {
  return isDeployed(chain) && /^0x0{40}$/i.test(chain.predicateAddress) === false;
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
