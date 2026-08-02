/**
 * THE CRITICAL INTEGRATION SEAM — the EIP-712 "humanity voucher".
 *
 * This module builds and signs the exact `HumanityVoucher` that Phase C's on-chain
 * `ProofOfHumanity.mintWithVoucher(voucher, signature)` recovers a signer from. If the domain,
 * the type, or the field encoding here diverge from the contract by a single byte, the on-chain
 * `ECDSA.recover` yields a different address and the mint reverts `InvalidSigner`.
 *
 * It is mirrored 1:1 against `contracts/src/ProofOfHumanity.sol`:
 *
 *   - EIP712("ProofOfHumanity", "1")  → domain { name:"ProofOfHumanity", version:"1", ... }
 *   - VOUCHER_TYPEHASH = keccak256(
 *       "HumanityVoucher(address to,uint256 nullifier,uint8 ageFlags,bytes3 nationality,"
 *       "uint8 gender,bool ofacClear,uint64 expiry)")  → the VOUCHER_TYPES field list below.
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
    { name: "ageFlags", type: "uint8" },
    { name: "nationality", type: "bytes3" },
    { name: "gender", type: "uint8" },
    { name: "ofacClear", type: "bool" },
    { name: "expiry", type: "uint64" },
  ],
} as const;

export const VOUCHER_PRIMARY_TYPE = "HumanityVoucher" as const;

/** The contract's EIP-712 domain constants (from `EIP712("ProofOfHumanity", "1")`). */
export const DOMAIN_NAME = "ProofOfHumanity" as const;
export const DOMAIN_VERSION = "1" as const;

/** A voucher as viem/the contract ABI expect it (bigint numerics, hex bytes3). */
export interface HumanityVoucher {
  to: Address;
  nullifier: bigint;
  ageFlags: number;
  /** bytes3 as a 3-byte (6 hex char) hex string, e.g. "0x415247" for "ARG". */
  nationality: Hex;
  gender: number;
  ofacClear: boolean;
  expiry: bigint;
}

/** JSON-safe voucher for transport over the relay (bigints as decimal strings). */
export interface SerializedVoucher {
  to: Address;
  nullifier: string;
  ageFlags: number;
  nationality: Hex;
  gender: number;
  ofacClear: boolean;
  expiry: string;
}

export function serializeVoucher(v: HumanityVoucher): SerializedVoucher {
  return {
    to: v.to,
    nullifier: v.nullifier.toString(),
    ageFlags: v.ageFlags,
    nationality: v.nationality,
    gender: v.gender,
    ofacClear: v.ofacClear,
    expiry: v.expiry.toString(),
  };
}

export function deserializeVoucher(v: SerializedVoucher): HumanityVoucher {
  return {
    to: v.to,
    nullifier: BigInt(v.nullifier),
    ageFlags: v.ageFlags,
    nationality: v.nationality,
    gender: v.gender,
    ofacClear: v.ofacClear,
    expiry: BigInt(v.expiry),
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
 * requires `== issuer`. Uses viem's `privateKeyToAccount(...).signTypedData(...)` exactly as the
 * task specifies.
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
              ATTRIBUTE MAPPING (Self discloseOutput → voucher)
//////////////////////////////////////////////////////////////*/

const AGE_13 = 0x01;
const AGE_18 = 0x02;
const AGE_21 = 0x04;
const AGE_65 = 0x08;

/**
 * ISO-3166-1 alpha-3 nationality string ("USA", "ARG", …) → `bytes3` = the 3 ASCII bytes.
 * "" / not exactly 3 chars → `0x000000` ("not disclosed"), matching `bytes3(0)` in the contract.
 */
export function nationalityToBytes3(nat: string | undefined | null): Hex {
  if (!nat || nat.length !== 3) return "0x000000";
  let hex = "0x";
  for (let i = 0; i < 3; i++) {
    hex += (nat.charCodeAt(i) & 0xff).toString(16).padStart(2, "0");
  }
  return hex as Hex;
}

/**
 * Gender MRZ sex string ("M" / "F" / "<") → `uint8` = `charCodeAt(0)`.
 * "" / absent → 0 ("not disclosed"). The contract renders 0x4D→"male", 0x46→"female", else "other".
 */
export function genderToUint8(gender: string | undefined | null): number {
  if (!gender || gender.length === 0) return 0;
  return gender.charCodeAt(0) & 0xff;
}

/**
 * `olderThan` lower bound (the proven minimum age, 0 if not disclosed) → `ageFlags` bitfield.
 * Because a proof of "≥ N" implies every ladder threshold ≤ N, we OR in each satisfied bit.
 */
export function olderThanToAgeFlags(olderThan: number): number {
  let flags = 0;
  if (olderThan >= 13) flags |= AGE_13;
  if (olderThan >= 18) flags |= AGE_18;
  if (olderThan >= 21) flags |= AGE_21;
  if (olderThan >= 65) flags |= AGE_65;
  return flags;
}

/**
 * Self OFAC result → `ofacClear`. Self returns `boolean[]` (one entry per OFAC list check;
 * `true` = passed/clear). `ofacClear` is true only if EVERY check passed. An older `boolean`
 * shape is tolerated. An empty array (OFAC not requested) → false (not attested clear).
 */
export function ofacToClear(ofac: boolean | boolean[] | undefined | null): boolean {
  if (Array.isArray(ofac)) return ofac.length > 0 && ofac.every(Boolean);
  return Boolean(ofac);
}

/** The subset of Self's `GenericDiscloseOutput` this app maps into a voucher. */
export interface DiscloseLike {
  nullifier: string;
  nationality?: string;
  gender?: string;
  /** Self's `minimumAge` is the proven lower bound ("olderThan"); "0"/absent = not disclosed. */
  minimumAge?: string;
  ofac?: boolean | boolean[];
}

/**
 * Map a verified Self `discloseOutput` + the bound recipient + an expiry into a full voucher.
 * `expiry` is the voucher deadline AND the on-chain credential expiry (Phase C uses one field).
 */
export function buildVoucherFromDisclose(opts: {
  discloseOutput: DiscloseLike;
  to: Address;
  expiry: bigint;
}): HumanityVoucher {
  const olderThan = opts.discloseOutput.minimumAge ? Number.parseInt(opts.discloseOutput.minimumAge, 10) || 0 : 0;
  return {
    to: opts.to,
    nullifier: BigInt(opts.discloseOutput.nullifier),
    ageFlags: olderThanToAgeFlags(olderThan),
    nationality: nationalityToBytes3(opts.discloseOutput.nationality),
    gender: genderToUint8(opts.discloseOutput.gender),
    ofacClear: ofacToClear(opts.discloseOutput.ofac),
    expiry: opts.expiry,
  };
}
