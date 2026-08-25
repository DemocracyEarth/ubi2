import { getAddress, isAddress, isHex, size, type Address, type Hex } from "viem";
import type { ChainConfig } from "../config";
import type { SignedForChain } from "./verification-record";
import { deserializeVoucher, type HumanityVoucher } from "./voucher";

export const SPONSORED_MINT_RECEIPT_SCHEMA = "poh-sponsored-mint-receipt" as const;
export const SPONSORED_MINT_RECEIPT_VERSION = 1 as const;

export type SponsoredMintEvent = "minted" | "refreshed";

/** Chain-verifiable evidence returned after the sponsor transaction is confirmed and re-read. */
export interface SponsoredMintEvidence {
  schema: typeof SPONSORED_MINT_RECEIPT_SCHEMA;
  version: typeof SPONSORED_MINT_RECEIPT_VERSION;
  status: "confirmed";
  event: SponsoredMintEvent;
  chainId: number;
  chainName: string;
  contract: Address;
  recipient: Address;
  tokenId: string;
  transactionHash: Hex;
  blockHash: Hex;
  blockNumber: string;
  confirmedAt: string;
}

/** Evidence available while a submitted transaction is waiting for a block. */
export interface SponsoredMintSubmission {
  schema: typeof SPONSORED_MINT_RECEIPT_SCHEMA;
  version: typeof SPONSORED_MINT_RECEIPT_VERSION;
  status: "submitted";
  chainId: number;
  chainName: string;
  contract: Address;
  recipient: Address;
  transactionHash: Hex;
  submittedAt: string;
}

export type SponsoredMintPublicEvidence = SponsoredMintEvidence | SponsoredMintSubmission;

export type SponsoredMintAttempt =
  | { status: "submitting"; attempts: number; startedAt: number }
  | { status: "submitted"; attempts: number; startedAt: number; transactionHash: Hex; submittedAt: number }
  | { status: "confirmed"; attempts: number; evidence: SponsoredMintEvidence }
  | { status: "failed"; attempts: number; failedAt: number; retryAfter: number; code: string };

export class SponsoredMintBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SponsoredMintBindingError";
  }
}

function sameAddress(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * Fail-closed binding checked immediately before any sponsor balance or transaction is touched.
 * The caller supplies only a chain id: recipient, nullifier, epoch, contract and signature all
 * come from the short-lived server record created by the verified Self callback.
 */
export function validateSponsoredMintBinding(input: {
  capabilityAddress: Address;
  chain: ChainConfig;
  signed: SignedForChain;
  proof: { nullifier: string; epoch: number };
}): HumanityVoucher {
  const { capabilityAddress, chain, signed, proof } = input;
  if (!isAddress(capabilityAddress)) {
    throw new SponsoredMintBindingError("The verification capability address is invalid.");
  }
  if (chain.network !== "testnet") {
    throw new SponsoredMintBindingError("Sponsored minting is restricted to explicit testnets.");
  }
  if (/^0x0{40}$/i.test(chain.pohAddress)) {
    throw new SponsoredMintBindingError("The selected testnet contract is not deployed.");
  }
  if (signed.chainId !== chain.chainId || signed.chainId <= 0 || !Number.isSafeInteger(signed.chainId)) {
    throw new SponsoredMintBindingError("The stored voucher is bound to a different chain.");
  }
  if (!sameAddress(signed.pohAddress, chain.pohAddress)) {
    throw new SponsoredMintBindingError("The stored voucher is bound to a different contract.");
  }
  if (!sameAddress(signed.voucher.to, capabilityAddress)) {
    throw new SponsoredMintBindingError("The stored voucher recipient does not match the verification capability.");
  }
  if (signed.voucher.nullifier !== proof.nullifier || signed.voucher.epoch !== proof.epoch) {
    throw new SponsoredMintBindingError("The stored voucher does not match the proof-derived record.");
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(signed.signature) || !isHex(signed.signature) || size(signed.signature) !== 65) {
    throw new SponsoredMintBindingError("The stored voucher signature is malformed.");
  }

  let voucher: HumanityVoucher;
  try {
    voucher = deserializeVoucher(signed.voucher);
  } catch {
    throw new SponsoredMintBindingError("The stored voucher values are malformed.");
  }
  if (voucher.nullifier <= 0n) {
    throw new SponsoredMintBindingError("The stored voucher nullifier is invalid.");
  }
  if (!Number.isSafeInteger(voucher.epoch) || voucher.epoch < 0 || voucher.epoch > 0xffff_ffff) {
    throw new SponsoredMintBindingError("The stored voucher epoch is invalid.");
  }
  return { ...voucher, to: getAddress(voucher.to) };
}

/** Parse an operator-controlled allowlist and prove that every id is an explicit public testnet. */
export function parseSponsoredTestnetAllowlist(raw: string, chains: readonly ChainConfig[]): number[] {
  const values = raw.split(",").map((value) => value.trim()).filter(Boolean);
  if (values.length === 0) throw new Error("POH_SPONSOR_TESTNET_CHAIN_IDS must list at least one chain id.");
  const ids = values.map((value) => {
    if (!/^[1-9][0-9]*$/.test(value)) {
      throw new Error("POH_SPONSOR_TESTNET_CHAIN_IDS must be a comma-separated list of positive integers.");
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) {
      throw new Error("POH_SPONSOR_TESTNET_CHAIN_IDS contains an unsafe chain id.");
    }
    return parsed;
  });
  const unique = [...new Set(ids)];
  for (const chainId of unique) {
    const chain = chains.find((candidate) => candidate.chainId === chainId);
    if (!chain || chain.network !== "testnet" || /^0x0{40}$/i.test(chain.pohAddress)) {
      throw new Error(`Sponsored mint chain ${chainId} is not a configured, deployed testnet.`);
    }
  }
  return unique;
}

export function sponsoredMintAttemptEvidence(
  attempt: SponsoredMintAttempt,
  chain: ChainConfig,
  recipient: Address,
): SponsoredMintPublicEvidence | null {
  if (attempt.status === "confirmed") return attempt.evidence;
  if (attempt.status !== "submitted") return null;
  return {
    schema: SPONSORED_MINT_RECEIPT_SCHEMA,
    version: SPONSORED_MINT_RECEIPT_VERSION,
    status: "submitted",
    chainId: chain.chainId,
    chainName: chain.name,
    contract: chain.pohAddress,
    recipient,
    transactionHash: attempt.transactionHash,
    submittedAt: new Date(attempt.submittedAt).toISOString(),
  };
}
