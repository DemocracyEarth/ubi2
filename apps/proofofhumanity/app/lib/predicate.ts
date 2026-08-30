/**
 * THE PREDICATE LAYER (v1) — EIP-712 SDK helpers.
 *
 * A verified human proves a yes/no PREDICATE about themselves ("age ≥ 18",
 * "nationality = ARG", "sanctions-clear") to a consumer, revealing ONLY the
 * boolean. Nothing personal is stored on-chain, and the proof is bound to a
 * single consumer, which limits replay. The artifact still exposes the subject
 * wallet and is therefore linkable when that wallet is reused across consumers.
 *
 * Two credentials live here — PIN the on-chain one exactly:
 *
 *   1. HumanCredential — TS-ONLY. The issuer signs it at Self verification; the
 *      holder keeps it PRIVATELY off-chain (sessionStorage in the product). It carries
 *      the raw predicate INPUTS (age flags, nationality, OFAC-clear) the issuer
 *      re-reads when asked to attest a predicate. It never touches Solidity, so
 *      its EIP-712 domain is PORTABLE — `{ name, version }` only (no chainId /
 *      verifyingContract), and it is verified purely in TypeScript.
 *
 *   2. PredicateAttestation — the v1 PROOF that crosses to Solidity. The issuer
 *      signs one per predicate-request, bound to a single `consumer` + `context`
 *      + `subject`. Its EIP-712 domain names the on-chain `PredicateVerifier`
 *      (`{ name, version, chainId, verifyingContract }`) so the digest — and thus
 *      the signature — is valid for exactly one verifier on one chain.
 *
 * ┌── TRUST MODEL (v1 = ISSUER-ATTESTED) ────────────────────────────────────┐
 * │ The issuer (the same trusted party that mints the SBT) COMPUTES the       │
 * │ boolean `result` from the HumanCredential attributes and signs it. This   │
 * │ mirrors how minting pairs a trusted `mintWithVoucher` with an (unbuilt)   │
 * │ ZK `IHumanityProofVerifier` seam. The trustless v2 replaces the issuer's  │
 * │ signature with a holder-side ZK proof over the held credential, dropped   │
 * │ into the `IPredicateProver` seam on `PredicateVerifier` — the ABI does    │
 * │ not change. The attributes here are the exact witness that ZK circuit     │
 * │ would consume.                                                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * PARITY CONTRACT: `PREDICATE_TYPES` + `PREDICATE_DOMAIN_NAME/VERSION` and the
 * `PredicateAttestation(...)` field order below are byte-identical to
 * `PredicateVerifier.sol`'s `PREDICATE_TYPEHASH` + `EIP712("ProofOfHumanityPredicate","1")`.
 * If a single byte diverges, `ECDSA.recover` on-chain yields a different address
 * and `consume` reverts `InvalidSigner`. `test/predicate.crossstack.ts` asserts
 * `hashPredicateAttestation(...) == PredicateVerifier.hashAttestation(...)`.
 *
 * This module is deliberately PURE (imports only `viem`), so the exact code the
 * `/api/predicate` route signs with is what the cross-stack test exercises.
 */

import { privateKeyToAccount } from "viem/accounts";
import {
  hashTypedData,
  keccak256,
  recoverTypedDataAddress,
  stringToBytes,
  toHex,
  type Address,
  type Hex,
} from "viem";

/*//////////////////////////////////////////////////////////////
                       EPOCH (mirror the SBT)
//////////////////////////////////////////////////////////////*/

/** Length of a validity epoch, in seconds — mirrors `EPOCH = 90 days` on both
 *  ProofOfHumanity and PredicateVerifier. */
export const EPOCH_SECONDS = 90 * 24 * 60 * 60;

/** How many epochs after issuance an attestation stays fresh — mirrors the
 *  verifier's `VALIDITY_EPOCHS = 4` (~1 year). */
export const VALIDITY_EPOCHS = 4;

/** `floor(now / 90 days)` as a uint32 — equal to the contracts' `currentEpoch()`. */
export function epochNow(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / 1000 / EPOCH_SECONDS);
}

/*//////////////////////////////////////////////////////////////
              HUMAN CREDENTIAL  (TS-only, portable domain)
//////////////////////////////////////////////////////////////*/

/**
 * The private, off-chain credential the issuer signs at verification and the
 * holder keeps. It carries the RAW predicate inputs — the witness the issuer
 * (v1) or the holder's ZK circuit (v2) evaluates predicates against.
 *
 *  - `nullifier`   : Self's unique-human nullifier (ties the credential to the SBT).
 *  - `ageFlags`    : a uint8 bitfield of age-threshold facts (see AGE_FLAG_*).
 *  - `nationality` : ISO 3166-1 alpha-3 code as `bytes3` (ASCII, e.g. "ARG" → 0x415247);
 *                    `0x000000` = undisclosed.
 *  - `ofacClear`   : true iff the OFAC sanctions screen passed.
 *  - `epoch`       : the coarse 90-day validity epoch it was issued in.
 */
export interface HumanCredential {
  nullifier: bigint;
  ageFlags: number;
  nationality: Hex; // bytes3
  ofacClear: boolean;
  epoch: number;
}

/** JSON-safe HumanCredential for transport (bigint nullifier as decimal string). */
export interface SerializedHumanCredential {
  nullifier: string;
  ageFlags: number;
  nationality: Hex;
  ofacClear: boolean;
  epoch: number;
}

export function serializeHumanCredential(c: HumanCredential): SerializedHumanCredential {
  return {
    nullifier: c.nullifier.toString(),
    ageFlags: c.ageFlags,
    nationality: c.nationality,
    ofacClear: c.ofacClear,
    epoch: c.epoch,
  };
}

export function deserializeHumanCredential(c: SerializedHumanCredential): HumanCredential {
  return {
    nullifier: BigInt(c.nullifier),
    ageFlags: c.ageFlags,
    nationality: c.nationality,
    ofacClear: c.ofacClear,
    epoch: c.epoch,
  };
}

/** EIP-712 type of the HumanCredential (field order is the signature contract). */
export const HUMAN_CREDENTIAL_TYPES = {
  HumanCredential: [
    { name: "nullifier", type: "uint256" },
    { name: "ageFlags", type: "uint8" },
    { name: "nationality", type: "bytes3" },
    { name: "ofacClear", type: "bool" },
    { name: "epoch", type: "uint32" },
  ],
} as const;

export const HUMAN_CREDENTIAL_PRIMARY_TYPE = "HumanCredential" as const;

/** PORTABLE domain — no chainId / verifyingContract, since the credential never
 *  touches a specific chain or contract. */
export const CREDENTIAL_DOMAIN_NAME = "ProofOfHumanityCredential" as const;
export const CREDENTIAL_DOMAIN_VERSION = "1" as const;

export function credentialDomain() {
  return { name: CREDENTIAL_DOMAIN_NAME, version: CREDENTIAL_DOMAIN_VERSION } as const;
}

/** The EIP-712 digest a signer signs for `credential` (portable domain). */
export function hashHumanCredential(credential: HumanCredential): Hex {
  return hashTypedData({
    domain: credentialDomain(),
    types: HUMAN_CREDENTIAL_TYPES,
    primaryType: HUMAN_CREDENTIAL_PRIMARY_TYPE,
    message: credential,
  });
}

/** Sign a HumanCredential with the issuer key (the private, held credential). */
export async function signHumanCredential(issuerPrivateKey: Hex, credential: HumanCredential): Promise<Hex> {
  const account = privateKeyToAccount(issuerPrivateKey);
  return account.signTypedData({
    domain: credentialDomain(),
    types: HUMAN_CREDENTIAL_TYPES,
    primaryType: HUMAN_CREDENTIAL_PRIMARY_TYPE,
    message: credential,
  });
}

/** Recover the address that signed a HumanCredential. */
export async function recoverHumanCredentialSigner(credential: HumanCredential, signature: Hex): Promise<Address> {
  return recoverTypedDataAddress({
    domain: credentialDomain(),
    types: HUMAN_CREDENTIAL_TYPES,
    primaryType: HUMAN_CREDENTIAL_PRIMARY_TYPE,
    message: credential,
    signature,
  });
}

/** True iff `signature` over `credential` recovers to `expectedIssuer`. This is
 *  the check the `/api/predicate` route runs before it will attest a predicate. */
export async function verifyHumanCredential(
  credential: HumanCredential,
  signature: Hex,
  expectedIssuer: Address,
): Promise<boolean> {
  const signer = await recoverHumanCredentialSigner(credential, signature);
  return signer.toLowerCase() === expectedIssuer.toLowerCase();
}

/*//////////////////////////////////////////////////////////////
              PREDICATE ATTESTATION  (crosses to Solidity)
//////////////////////////////////////////////////////////////*/

/**
 * The v1 proof: the issuer's signed assertion that `subject` satisfies
 * `predicate` (as a boolean `result`), for one `consumer` in one `context`.
 * Field order + Solidity types MUST match `PREDICATE_TYPEHASH` in
 * `PredicateVerifier.sol` exactly.
 */
export interface PredicateAttestation {
  /** The verifying consumer contract/app — binds the proof to one consumer. */
  consumer: Address;
  /** Consumer-defined scope (e.g. a proposal id), as bytes32. */
  context: Hex;
  /** `keccak256(<canonical descriptor>)` — the predicate being proven. */
  predicate: Hex;
  /** The boolean the issuer computed from the HumanCredential. */
  result: boolean;
  /** The presenting human's address — binds the proof to the presenter. */
  subject: Address;
  /** The validity epoch (matches the credential; the verifier checks freshness). */
  epoch: number;
  /** Anti-replay salt. */
  nonce: bigint;
}

/** JSON-safe PredicateAttestation for transport (bigint nonce as decimal string). */
export interface SerializedPredicateAttestation {
  consumer: Address;
  context: Hex;
  predicate: Hex;
  result: boolean;
  subject: Address;
  epoch: number;
  nonce: string;
}

export function serializePredicateAttestation(a: PredicateAttestation): SerializedPredicateAttestation {
  return {
    consumer: a.consumer,
    context: a.context,
    predicate: a.predicate,
    result: a.result,
    subject: a.subject,
    epoch: a.epoch,
    nonce: a.nonce.toString(),
  };
}

export function deserializePredicateAttestation(a: SerializedPredicateAttestation): PredicateAttestation {
  return {
    consumer: a.consumer,
    context: a.context,
    predicate: a.predicate,
    result: a.result,
    subject: a.subject,
    epoch: a.epoch,
    nonce: BigInt(a.nonce),
  };
}

/**
 * EIP-712 type of the attestation — field order + Solidity types are byte-identical
 * to `PredicateVerifier.sol`'s:
 *   keccak256("PredicateAttestation(address consumer,bytes32 context,bytes32 predicate,bool result,address subject,uint32 epoch,uint256 nonce)")
 */
export const PREDICATE_TYPES = {
  PredicateAttestation: [
    { name: "consumer", type: "address" },
    { name: "context", type: "bytes32" },
    { name: "predicate", type: "bytes32" },
    { name: "result", type: "bool" },
    { name: "subject", type: "address" },
    { name: "epoch", type: "uint32" },
    { name: "nonce", type: "uint256" },
  ],
} as const;

export const PREDICATE_PRIMARY_TYPE = "PredicateAttestation" as const;

/** The verifier contract's EIP-712 domain constants (from `EIP712("ProofOfHumanityPredicate","1")`). */
export const PREDICATE_DOMAIN_NAME = "ProofOfHumanityPredicate" as const;
export const PREDICATE_DOMAIN_VERSION = "1" as const;

/** Build the EIP-712 domain for a given chain + deployed PredicateVerifier address. */
export function predicateDomain(chainId: number, verifyingContract: Address) {
  return {
    name: PREDICATE_DOMAIN_NAME,
    version: PREDICATE_DOMAIN_VERSION,
    chainId,
    verifyingContract,
  } as const;
}

/**
 * The EIP-712 digest a signer must sign for `att` on (chainId, verifyingContract).
 * Equal — byte-for-byte — to `PredicateVerifier.hashAttestation(att)`; the
 * cross-stack test asserts exactly this.
 */
export function hashPredicateAttestation(att: PredicateAttestation, chainId: number, verifyingContract: Address): Hex {
  return hashTypedData({
    domain: predicateDomain(chainId, verifyingContract),
    types: PREDICATE_TYPES,
    primaryType: PREDICATE_PRIMARY_TYPE,
    message: att,
  });
}

/** Sign a PredicateAttestation with the issuer key. This is THE signature
 *  `PredicateVerifier.consume/check` recovers and requires `== issuer`. */
export async function signPredicateAttestation(
  issuerPrivateKey: Hex,
  att: PredicateAttestation,
  chainId: number,
  verifyingContract: Address,
): Promise<Hex> {
  const account = privateKeyToAccount(issuerPrivateKey);
  return account.signTypedData({
    domain: predicateDomain(chainId, verifyingContract),
    types: PREDICATE_TYPES,
    primaryType: PREDICATE_PRIMARY_TYPE,
    message: att,
  });
}

/** Recover the signer of a PredicateAttestation (for off-chain verification). */
export async function recoverPredicateSigner(
  att: PredicateAttestation,
  signature: Hex,
  chainId: number,
  verifyingContract: Address,
): Promise<Address> {
  return recoverTypedDataAddress({
    domain: predicateDomain(chainId, verifyingContract),
    types: PREDICATE_TYPES,
    primaryType: PREDICATE_PRIMARY_TYPE,
    message: att,
    signature,
  });
}

/*//////////////////////////////////////////////////////////////
                    THE DESCRIPTOR GRAMMAR
//////////////////////////////////////////////////////////////*/

/**
 * Canonical predicate descriptors (v1). `predicate` on an attestation is
 * `descriptorHash(descriptor)` — the plaintext descriptor is agreed off-chain
 * (a consumer publishes the descriptor it requires; the hash is what binds).
 *
 * Grammar (exhaustive in v1):
 *   age>=18            → holder is at least 18   (AGE_FLAG_18 set)
 *   age>=21            → holder is at least 21   (AGE_FLAG_21 set)
 *   nationality=CCC    → holder's nationality == CCC (ISO 3166-1 alpha-3, uppercase)
 *   sanctions-clear    → holder passed the OFAC screen (ofacClear)
 *
 * Descriptors are case-sensitive and whitespace-free. keccak256 is over the
 * UTF-8 bytes of the canonical string, matching Solidity `keccak256(bytes(descriptor))`.
 */
export type PredicateDescriptor = "age>=18" | "age>=21" | "sanctions-clear" | `nationality=${string}`;

/** uint8 age-threshold bitfield packed into `HumanCredential.ageFlags`. */
export const AGE_FLAG_18 = 0x01;
export const AGE_FLAG_21 = 0x02;

/** Pack a disclosed age (or nothing) into the age-threshold bitfield. */
export function buildAgeFlags(age: number | undefined): number {
  let flags = 0;
  if (age === undefined) return flags;
  if (age >= 18) flags |= AGE_FLAG_18;
  if (age >= 21) flags |= AGE_FLAG_21;
  return flags;
}

/** Pack a set of proven "olderThan" thresholds into the bitfield (Self discloses
 *  a boolean "older than N", not the exact age). */
export function ageFlagsFromThresholds(opts: { over18?: boolean; over21?: boolean }): number {
  let flags = 0;
  if (opts.over18) flags |= AGE_FLAG_18;
  if (opts.over21) flags |= AGE_FLAG_18 | AGE_FLAG_21; // over 21 ⇒ over 18
  return flags;
}

/** Encode an ISO 3166-1 alpha-3 country code (e.g. "ARG") as a `bytes3` hex. */
export function nationalityToBytes3(code: string): Hex {
  const up = code.toUpperCase();
  if (!/^[A-Z]{3}$/.test(up)) throw new Error(`Invalid ISO alpha-3 country code: ${code}`);
  return toHex(stringToBytes(up)) as Hex; // 3 ASCII bytes → 0x + 6 hex
}

/** Decode a `bytes3` nationality back to its ISO alpha-3 code ("" if undisclosed). */
export function bytes3ToNationality(b: Hex): string {
  const hex = b.replace(/^0x/, "").padStart(6, "0").slice(0, 6);
  if (hex === "000000") return "";
  let out = "";
  for (let i = 0; i < 6; i += 2) out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

/** `keccak256(utf8Bytes(descriptor))` — matches Solidity `keccak256(bytes(descriptor))`. */
export function descriptorHash(descriptor: string): Hex {
  return keccak256(stringToBytes(descriptor));
}

/** The attributes an evaluator reads (a subset of the HumanCredential). */
export interface PredicateAttrs {
  ageFlags: number;
  nationality: Hex;
  ofacClear: boolean;
}

/**
 * Evaluate a canonical descriptor against a holder's attributes → the boolean
 * the issuer signs as `result`. Throws on an unknown descriptor (fail-closed:
 * the issuer never attests a predicate it cannot parse).
 */
export function evalPredicate(descriptor: string, attrs: PredicateAttrs): boolean {
  const d = descriptor.trim();
  if (d === "age>=18") return (attrs.ageFlags & AGE_FLAG_18) !== 0;
  if (d === "age>=21") return (attrs.ageFlags & AGE_FLAG_21) !== 0;
  if (d === "sanctions-clear") return attrs.ofacClear === true;
  const m = /^nationality=([A-Z]{3})$/.exec(d);
  if (m) return attrs.nationality.toLowerCase() === nationalityToBytes3(m[1]).toLowerCase();
  throw new Error(`Unknown predicate descriptor: ${JSON.stringify(descriptor)}`);
}
