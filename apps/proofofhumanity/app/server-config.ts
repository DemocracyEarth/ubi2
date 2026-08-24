import "server-only";

import { getAddress, isAddress, isHex, size, type Address, type Hex } from "viem";
import { CHAINS } from "./config";
import { parseSponsoredTestnetAllowlist } from "./lib/sponsored-mint";

const ANVIL_ISSUER_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;

/**
 * Return the issuer signer only from server code. Production fails closed when the secret is
 * missing; the well-known Anvil key is available solely to local development and tests.
 */
export function getIssuerPrivateKey(): Hex {
  const key = process.env.ISSUER_PRIVATE_KEY;
  if (key) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
      throw new Error("ISSUER_PRIVATE_KEY must be a 32-byte 0x-prefixed hex key.");
    }
    return key as Hex;
  }
  if (process.env.NODE_ENV !== "production") return ANVIL_ISSUER_KEY;
  throw new Error("ISSUER_PRIVATE_KEY is required in production.");
}

export interface SponsoredMintServerConfig {
  privateKey: Hex;
  enabledChainIds: readonly number[];
  maxGas: bigint;
  maxFeeWei: bigint;
  minimumReserveWei: bigint;
  confirmations: number;
  receiptTimeoutMs: number;
  dailyTransactionLimit: number;
}

function positiveBigIntEnv(name: string, value: string | undefined, fallback: bigint): bigint {
  if (!value) return fallback;
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${name} must be a positive integer.`);
  return BigInt(value);
}

function boundedIntegerEnv(
  name: string,
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (!value) return fallback;
  if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be an integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

/**
 * Optional testnet sponsor. It has no development fallback and is enabled only when both the
 * isolated hot key and an explicit allowlist are present. Mainnet ids fail during configuration.
 */
export function getSponsoredMintServerConfig(): SponsoredMintServerConfig | null {
  const privateKey = process.env.POH_SPONSOR_PRIVATE_KEY?.trim();
  const allowlist = process.env.POH_SPONSOR_TESTNET_CHAIN_IDS?.trim();
  if (!privateKey && !allowlist) return null;
  if (!privateKey || !allowlist) {
    throw new Error(
      "POH_SPONSOR_PRIVATE_KEY and POH_SPONSOR_TESTNET_CHAIN_IDS must be configured together.",
    );
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey) || BigInt(privateKey) === 0n) {
    throw new Error("POH_SPONSOR_PRIVATE_KEY must be a non-zero 32-byte 0x-prefixed hex key.");
  }

  return {
    privateKey: privateKey as Hex,
    enabledChainIds: parseSponsoredTestnetAllowlist(allowlist, CHAINS),
    maxGas: positiveBigIntEnv("POH_SPONSOR_MAX_GAS", process.env.POH_SPONSOR_MAX_GAS, 350_000n),
    maxFeeWei: positiveBigIntEnv(
      "POH_SPONSOR_MAX_FEE_WEI",
      process.env.POH_SPONSOR_MAX_FEE_WEI,
      5_000_000_000_000_000n,
    ),
    minimumReserveWei: positiveBigIntEnv(
      "POH_SPONSOR_MIN_RESERVE_WEI",
      process.env.POH_SPONSOR_MIN_RESERVE_WEI,
      1_000_000_000_000_000n,
    ),
    confirmations: boundedIntegerEnv(
      "POH_SPONSOR_CONFIRMATIONS",
      process.env.POH_SPONSOR_CONFIRMATIONS,
      1,
      1,
      12,
    ),
    receiptTimeoutMs: boundedIntegerEnv(
      "POH_SPONSOR_RECEIPT_TIMEOUT_MS",
      process.env.POH_SPONSOR_RECEIPT_TIMEOUT_MS,
      90_000,
      5_000,
      300_000,
    ),
    dailyTransactionLimit: boundedIntegerEnv(
      "POH_SPONSOR_DAILY_TX_LIMIT",
      process.env.POH_SPONSOR_DAILY_TX_LIMIT,
      100,
      1,
      10_000,
    ),
  };
}

export interface ZkSelfIssuanceServerConfig {
  chainId: number;
  rpcUrl: string;
  registry: Address;
  bridge: Address;
  issuerKeyId: Hex;
  authorityPrivateKey: Hex;
}

/**
 * Optional v2 bridge configuration. It is disabled only when every related
 * variable is absent; a partial configuration fails closed.
 */
export function getZkSelfIssuanceServerConfig(): ZkSelfIssuanceServerConfig | null {
  const values = {
    chainId: process.env.ZK_SELF_ISSUANCE_CHAIN_ID,
    rpcUrl: process.env.ZK_SELF_ISSUANCE_RPC_URL,
    registry: process.env.ZK_SELF_ISSUANCE_REGISTRY,
    bridge: process.env.ZK_SELF_ISSUANCE_BRIDGE,
    issuerKeyId: process.env.ZK_SELF_ISSUER_KEY_ID,
    authorityPrivateKey: process.env.ZK_SELF_ISSUANCE_AUTHORITY_PRIVATE_KEY,
  };
  if (Object.values(values).every((value) => !value)) return null;

  const missing = Object.entries(values)
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`Incomplete v2 Self issuance configuration: missing ${missing.join(", ")}.`);
  }

  const parsedChainId = Number(values.chainId);
  if (!Number.isSafeInteger(parsedChainId) || parsedChainId <= 0) {
    throw new Error("ZK_SELF_ISSUANCE_CHAIN_ID must be a positive integer.");
  }
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(values.rpcUrl!);
  } catch {
    throw new Error("ZK_SELF_ISSUANCE_RPC_URL must be an absolute URL.");
  }
  if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
    throw new Error("ZK_SELF_ISSUANCE_RPC_URL must use http or https.");
  }
  if (!isAddress(values.registry!) || BigInt(values.registry!) === 0n) {
    throw new Error("ZK_SELF_ISSUANCE_REGISTRY must be a non-zero EVM address.");
  }
  if (!isAddress(values.bridge!) || BigInt(values.bridge!) === 0n) {
    throw new Error("ZK_SELF_ISSUANCE_BRIDGE must be a non-zero EVM address.");
  }
  if (!isHex(values.issuerKeyId!) || size(values.issuerKeyId! as Hex) !== 32 || BigInt(values.issuerKeyId!) === 0n) {
    throw new Error("ZK_SELF_ISSUER_KEY_ID must be a non-zero bytes32 value.");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(values.authorityPrivateKey!)) {
    throw new Error("ZK_SELF_ISSUANCE_AUTHORITY_PRIVATE_KEY must be a 32-byte 0x-prefixed hex key.");
  }

  return {
    chainId: parsedChainId,
    rpcUrl: values.rpcUrl!,
    registry: getAddress(values.registry!),
    bridge: getAddress(values.bridge!),
    issuerKeyId: values.issuerKeyId!.toLowerCase() as Hex,
    authorityPrivateKey: values.authorityPrivateKey! as Hex,
  };
}
