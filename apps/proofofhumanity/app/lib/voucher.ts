/**
 * THE CRITICAL INTEGRATION SEAM — the EIP-712 "humanity voucher".
 *
 * This module builds and signs the exact `HumanityVoucher` that the on-chain
 * `ProofOfHumanity.mintWithVoucher(voucher, signature)` recovers a signer from. If the domain,
 * the type, or the field encoding here diverge from the contract by a single byte, the on-chain
 * `ECDSA.recover` yields a different address and the mint reverts `InvalidSigner`.
 *
 * The voucher is DELIBERATELY MINIMAL: it carries no personal data. It asserts only
 *   - `to`         : the address that receives the soulbound credential;
 *   - `nullifier`  : Self's deterministic per-identity nullifier (proves ONE unique human,
 *                    reveals nothing about who they are);
 *   - `epoch`      : the coarse 90-day validity epoch the human was verified in.
 * No nationality / gender / age / OFAC values ever enter the voucher — those remain zero-knowledge
 * predicates a holder can prove on demand, never stored on-chain.
 *
 * It is mirrored 1:1 against `contracts/src/ProofOfHumanity.sol`:
 *
 *   - EIP712("ProofOfHumanity", "1")  → domain { name:"ProofOfHumanity", version:"1", ... }
 *   - VOUCHER_TYPEHASH = keccak256(
 *       "HumanityVoucher(address to,uint256 nullifier,uint32 epoch)")  → VOUCHER_TYPES below.
 *
 * The `chainId` + `verifyingContract` in the domain are the target chain's id and the
 * ProofOfHumanity address deployed on THAT chain (the contract uses `block.chainid` +
 * `address(this)`), so a single signature is valid on exactly one chain. The relay therefore
 * signs one voucher per configured chain.
 *
 * This file is deliberately PURE: it imports only `viem` and has no Next.js / Node / browser
 * dependencies, so the exact same code that the relay signs with is what the cross-stack test
 * (test/voucher.crossstack.ts) exercises against a real deployed contract.
 */

import { privateKeyToAccount } from "viem/accounts";
import { hashTypedData, type Address, type Hex } from "viem";

/**
 * EIP-712 type of the voucher — field order and Solidity types MUST match
 * `VOUCHER_TYPEHASH` in ProofOfHumanity.sol exactly.
 */
export const VOUCHER_TYPES = {
  HumanityVoucher: [
    { name: "to", type: "address" },
    { name: "nullifier", type: "uint256" },
    { name: "epoch", type: "uint32" },
  ],
} as const;

export const VOUCHER_PRIMARY_TYPE = "HumanityVoucher" as const;

/** The contract's EIP-712 domain constants (from `EIP712("ProofOfHumanity", "1")`). */
export const DOMAIN_NAME = "ProofOfHumanity" as const;
export const DOMAIN_VERSION = "1" as const;

/**
 * The coarse validity epoch, in seconds. Mirrors the contract's
 * `uint256 constant EPOCH = 90 days;`. `epochNow()` == the contract's `currentEpoch()`.
 * A credential stores the epoch it was verified in; validity is a small window of epochs after it,
 * so the ONLY time-derived fact on-chain is a coarse ~90-day bucket — never a passport date.
 */
export const EPOCH_SECONDS = 90 * 24 * 60 * 60;

/** `floor(now / 90 days)` as a uint32 — equal to the contract's `currentEpoch()`. */
export function epochNow(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / 1000 / EPOCH_SECONDS);
}

/** A voucher as viem/the contract ABI expect it (bigint nullifier, uint32 epoch as number). */
export interface HumanityVoucher {
  to: Address;
  nullifier: bigint;
  /** The 90-day validity epoch the human was verified in (uint32). */
  epoch: number;
}

/** JSON-safe voucher for transport over the relay (bigint nullifier as decimal string). */
export interface SerializedVoucher {
  to: Address;
  nullifier: string;
  epoch: number;
}

export function serializeVoucher(v: HumanityVoucher): SerializedVoucher {
  return {
    to: v.to,
    nullifier: v.nullifier.toString(),
    epoch: v.epoch,
  };
}

export function deserializeVoucher(v: SerializedVoucher): HumanityVoucher {
  return {
    to: v.to,
    nullifier: BigInt(v.nullifier),
    epoch: v.epoch,
  };
}

/** Build the EIP-712 domain for a given target chain + deployed ProofOfHumanity address. */
export function voucherDomain(chainId: number, verifyingContract: Address) {
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId,
    verifyingContract,
  } as const;
}

/**
 * The EIP-712 digest a signer must sign for `voucher` on (chainId, verifyingContract).
 * Equal — byte-for-byte — to the contract's `hashVoucher(voucher)` view; the cross-stack test
 * asserts exactly this.
 */
export function voucherDigest(voucher: HumanityVoucher, chainId: number, verifyingContract: Address): Hex {
  return hashTypedData({
    domain: voucherDomain(chainId, verifyingContract),
    types: VOUCHER_TYPES,
    primaryType: VOUCHER_PRIMARY_TYPE,
    message: voucher,
  });
}

/**
 * Sign a voucher with the issuer key. This is THE signature `mintWithVoucher` recovers and
 * requires `== issuer`. Uses viem's `privateKeyToAccount(...).signTypedData(...)`.
 */
export async function signVoucher(
  issuerPrivateKey: Hex,
  voucher: HumanityVoucher,
  chainId: number,
  verifyingContract: Address,
): Promise<Hex> {
  const account = privateKeyToAccount(issuerPrivateKey);
  return account.signTypedData({
    domain: voucherDomain(chainId, verifyingContract),
    types: VOUCHER_TYPES,
    primaryType: VOUCHER_PRIMARY_TYPE,
    message: voucher,
  });
}

/*//////////////////////////////////////////////////////////////
              PROOF → VOUCHER (minimal: nullifier only)
//////////////////////////////////////////////////////////////*/

/**
 * The single field this app reads out of Self's verified proof: the nullifier that proves a
 * unique human. Nationality / gender / age / OFAC are intentionally NOT mapped into the
 * credential — they stay zero-knowledge predicates, provable on demand.
 */
export interface DiscloseLike {
  nullifier: string;
}

/**
 * Map a verified Self proof + the bound recipient + the current epoch into a minimal voucher.
 * `epoch` defaults to `epochNow()`; pass one explicitly only for deterministic tests.
 */
export function buildVoucher(opts: {
  discloseOutput: DiscloseLike;
  to: Address;
  epoch?: number;
}): HumanityVoucher {
  return {
    to: opts.to,
    nullifier: BigInt(opts.discloseOutput.nullifier),
    epoch: opts.epoch ?? epochNow(),
  };
}
