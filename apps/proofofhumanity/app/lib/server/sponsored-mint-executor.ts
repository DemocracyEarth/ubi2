import "server-only";

import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  defineChain,
  http,
  recoverAddress,
  type Address,
  type Hex,
  type TransactionReceipt,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { proofOfHumanityAbi } from "../../abi/proofOfHumanity";
import type { ChainConfig } from "../../config";
import {
  SPONSORED_MINT_RECEIPT_SCHEMA,
  SPONSORED_MINT_RECEIPT_VERSION,
  type SponsoredMintEvidence,
  type SponsoredMintEvent,
} from "../sponsored-mint";
import { voucherDigest, type HumanityVoucher } from "../voucher";
import type { SponsoredMintServerConfig } from "../../server-config";

export type SponsoredMintFailureCode =
  | "policy-disabled"
  | "chain-mismatch"
  | "contract-mismatch"
  | "signer-role-overlap"
  | "issuer-mismatch"
  | "voucher-expired"
  | "gas-limit"
  | "fee-limit"
  | "sponsor-balance"
  | "simulation-rejected"
  | "transaction-reverted"
  | "receipt-mismatch";

export class SponsoredMintExecutionError extends Error {
  constructor(
    readonly code: SponsoredMintFailureCode,
    readonly terminal: boolean,
  ) {
    super(code);
    this.name = "SponsoredMintExecutionError";
  }
}

export interface SponsoredMintExecutionInput {
  chain: ChainConfig;
  voucher: HumanityVoucher;
  signature: Hex;
  config: SponsoredMintServerConfig;
}

export interface SponsoredMintSubmitted {
  transactionHash: Hex;
  submittedAt: number;
}

const processState = globalThis as typeof globalThis & {
  __pohSponsorSubmissionTails?: Map<string, Promise<void>>;
};
const submissionTails = (processState.__pohSponsorSubmissionTails ??= new Map());

/** Serialize one sponsor account's submissions per chain so concurrent sessions cannot race a nonce. */
async function withSubmissionLock<T>(key: string, task: () => Promise<T>): Promise<T> {
  const previous = submissionTails.get(key) ?? Promise.resolve();
  let release = () => {};
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const queued = previous.catch(() => {}).then(() => current);
  submissionTails.set(key, queued);
  await previous.catch(() => {});
  try {
    return await task();
  } finally {
    release();
    if (submissionTails.get(key) === queued) submissionTails.delete(key);
  }
}

function chainForViem(chain: ChainConfig) {
  return defineChain({
    id: chain.chainId,
    name: chain.name,
    nativeCurrency: { name: "Testnet native token", symbol: "TEST", decimals: 18 },
    rpcUrls: { default: { http: [chain.rpcUrl] } },
  });
}

function sameAddress(a: string | null | undefined, b: string): boolean {
  return typeof a === "string" && a.toLowerCase() === b.toLowerCase();
}

function clients(input: SponsoredMintExecutionInput) {
  const chain = chainForViem(input.chain);
  const account = privateKeyToAccount(input.config.privateKey);
  return {
    account,
    publicClient: createPublicClient({ chain, transport: http(input.chain.rpcUrl, { retryCount: 1, timeout: 15_000 }) }),
    walletClient: createWalletClient({ account, chain, transport: http(input.chain.rpcUrl, { retryCount: 1, timeout: 15_000 }) }),
  };
}

function enforceStaticPolicy(input: SponsoredMintExecutionInput): void {
  if (
    input.chain.network !== "testnet" ||
    !input.config.enabledChainIds.includes(input.chain.chainId) ||
    /^0x0{40}$/i.test(input.chain.pohAddress)
  ) {
    throw new SponsoredMintExecutionError("policy-disabled", true);
  }
}

/** Preflight every trust and budget invariant, then submit exactly the proof-bound voucher. */
export async function submitSponsoredMint(
  input: SponsoredMintExecutionInput,
): Promise<SponsoredMintSubmitted> {
  enforceStaticPolicy(input);
  const sponsor = privateKeyToAccount(input.config.privateKey);
  return withSubmissionLock(`${input.chain.chainId}:${sponsor.address.toLowerCase()}`, () =>
    submitSponsoredMintLocked(input),
  );
}

async function submitSponsoredMintLocked(
  input: SponsoredMintExecutionInput,
): Promise<SponsoredMintSubmitted> {
  const { account, publicClient, walletClient } = clients(input);
  if (sameAddress(account.address, input.voucher.to)) {
    throw new SponsoredMintExecutionError("signer-role-overlap", true);
  }

  const [rpcChainId, bytecode, issuer, owner, currentEpoch] = await Promise.all([
    publicClient.getChainId(),
    publicClient.getBytecode({ address: input.chain.pohAddress }),
    publicClient.readContract({
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "issuer",
    }),
    publicClient.readContract({
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "owner",
    }),
    publicClient.readContract({
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "currentEpoch",
    }),
  ]);
  if (rpcChainId !== input.chain.chainId) {
    throw new SponsoredMintExecutionError("chain-mismatch", true);
  }
  if (!bytecode || bytecode === "0x") {
    throw new SponsoredMintExecutionError("contract-mismatch", true);
  }
  if (sameAddress(account.address, issuer) || sameAddress(account.address, owner)) {
    throw new SponsoredMintExecutionError("signer-role-overlap", true);
  }
  let voucherSigner: Address;
  try {
    voucherSigner = await recoverAddress({
      hash: voucherDigest(input.voucher, input.chain.chainId, input.chain.pohAddress),
      signature: input.signature,
    });
  } catch {
    throw new SponsoredMintExecutionError("issuer-mismatch", true);
  }
  if (!sameAddress(voucherSigner, issuer)) {
    throw new SponsoredMintExecutionError("issuer-mismatch", true);
  }
  if (input.voucher.epoch > currentEpoch || currentEpoch - input.voucher.epoch > 1) {
    throw new SponsoredMintExecutionError("voucher-expired", true);
  }

  let estimatedGas: bigint;
  try {
    estimatedGas = await publicClient.estimateContractGas({
      account,
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "mintWithVoucher",
      args: [input.voucher, input.signature],
    });
  } catch {
    throw new SponsoredMintExecutionError("simulation-rejected", true);
  }
  if (estimatedGas > input.config.maxGas) {
    throw new SponsoredMintExecutionError("gas-limit", true);
  }

  const gasLimit = estimatedGas + estimatedGas / 5n > input.config.maxGas
    ? input.config.maxGas
    : estimatedGas + estimatedGas / 5n;
  const [gasPrice, balance] = await Promise.all([
    publicClient.getGasPrice(),
    publicClient.getBalance({ address: account.address }),
  ]);
  const maximumFee = gasLimit * gasPrice;
  if (maximumFee > input.config.maxFeeWei) {
    throw new SponsoredMintExecutionError("fee-limit", false);
  }
  if (balance < maximumFee + input.config.minimumReserveWei) {
    throw new SponsoredMintExecutionError("sponsor-balance", false);
  }

  try {
    await publicClient.simulateContract({
      account,
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "mintWithVoucher",
      args: [input.voucher, input.signature],
    });
  } catch {
    throw new SponsoredMintExecutionError("simulation-rejected", true);
  }
  const transactionHash = await walletClient.writeContract({
    account,
    address: input.chain.pohAddress,
    abi: proofOfHumanityAbi,
    functionName: "mintWithVoucher",
    args: [input.voucher, input.signature],
    gas: gasLimit,
    gasPrice,
  });
  return { transactionHash, submittedAt: Date.now() };
}

function eventFromReceipt(
  receipt: TransactionReceipt,
  input: SponsoredMintExecutionInput,
  tokenId: bigint,
): SponsoredMintEvent {
  let match: SponsoredMintEvent | null = null;
  for (const log of receipt.logs) {
    if (!sameAddress(log.address, input.chain.pohAddress)) continue;
    try {
      const decoded = decodeEventLog({ abi: proofOfHumanityAbi, data: log.data, topics: log.topics });
      if (decoded.eventName === "HumanityMinted") {
        const args = decoded.args;
        if (
          args.tokenId === tokenId &&
          args.nullifier === input.voucher.nullifier &&
          sameAddress(args.to, input.voucher.to)
        ) {
          if (match) throw new SponsoredMintExecutionError("receipt-mismatch", true);
          match = "minted";
        }
      } else if (decoded.eventName === "HumanityRefreshed") {
        const args = decoded.args;
        if (
          args.tokenId === tokenId &&
          args.nullifier === input.voucher.nullifier &&
          args.epoch === input.voucher.epoch
        ) {
          if (match) throw new SponsoredMintExecutionError("receipt-mismatch", true);
          match = "refreshed";
        }
      }
    } catch (error) {
      if (error instanceof SponsoredMintExecutionError) throw error;
      // Other contract logs are intentionally ignored.
    }
  }
  if (!match) throw new SponsoredMintExecutionError("receipt-mismatch", true);
  return match;
}

async function verifyReceipt(
  input: SponsoredMintExecutionInput,
  receipt: TransactionReceipt,
): Promise<SponsoredMintEvidence> {
  const { account, publicClient } = clients(input);
  if (receipt.status !== "success") {
    throw new SponsoredMintExecutionError("transaction-reverted", true);
  }
  if (!sameAddress(receipt.from, account.address) || !sameAddress(receipt.to, input.chain.pohAddress)) {
    throw new SponsoredMintExecutionError("receipt-mismatch", true);
  }

  const tokenId = await publicClient.readContract({
    address: input.chain.pohAddress,
    abi: proofOfHumanityAbi,
    functionName: "tokenOfNullifier",
    args: [input.voucher.nullifier],
    blockNumber: receipt.blockNumber,
  });
  if (tokenId === 0n) throw new SponsoredMintExecutionError("receipt-mismatch", true);
  const [owner, valid, locked, block] = await Promise.all([
    publicClient.readContract({
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "ownerOf",
      args: [tokenId],
      blockNumber: receipt.blockNumber,
    }),
    publicClient.readContract({
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "isValid",
      args: [tokenId],
      blockNumber: receipt.blockNumber,
    }),
    publicClient.readContract({
      address: input.chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "locked",
      args: [tokenId],
      blockNumber: receipt.blockNumber,
    }),
    publicClient.getBlock({ blockNumber: receipt.blockNumber }),
  ]);
  if (!sameAddress(owner, input.voucher.to) || !valid || !locked) {
    throw new SponsoredMintExecutionError("receipt-mismatch", true);
  }
  const event = eventFromReceipt(receipt, input, tokenId);

  return {
    schema: SPONSORED_MINT_RECEIPT_SCHEMA,
    version: SPONSORED_MINT_RECEIPT_VERSION,
    status: "confirmed",
    event,
    chainId: input.chain.chainId,
    chainName: input.chain.name,
    contract: input.chain.pohAddress,
    recipient: input.voucher.to,
    tokenId: tokenId.toString(),
    transactionHash: receipt.transactionHash,
    blockHash: receipt.blockHash,
    blockNumber: receipt.blockNumber.toString(),
    confirmedAt: new Date(Number(block.timestamp) * 1_000).toISOString(),
  };
}

/** Wait for a submitted tx, then verify receipt sender/target/event and the post-state at that block. */
export async function waitForSponsoredMintEvidence(
  input: SponsoredMintExecutionInput,
  transactionHash: Hex,
): Promise<SponsoredMintEvidence> {
  enforceStaticPolicy(input);
  const { publicClient } = clients(input);
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: transactionHash,
    confirmations: input.config.confirmations,
    timeout: input.config.receiptTimeoutMs,
  });
  return verifyReceipt(input, receipt);
}

/** Non-blocking receipt check used to recover a response after the initial request times out. */
export async function readSponsoredMintEvidence(
  input: SponsoredMintExecutionInput,
  transactionHash: Hex,
): Promise<SponsoredMintEvidence | null> {
  enforceStaticPolicy(input);
  const { publicClient } = clients(input);
  let receipt: TransactionReceipt;
  try {
    receipt = await publicClient.getTransactionReceipt({ hash: transactionHash });
  } catch {
    return null;
  }
  const latestBlock = await publicClient.getBlockNumber();
  const confirmations = latestBlock - receipt.blockNumber + 1n;
  if (confirmations < BigInt(input.config.confirmations)) return null;
  return verifyReceipt(input, receipt);
}
