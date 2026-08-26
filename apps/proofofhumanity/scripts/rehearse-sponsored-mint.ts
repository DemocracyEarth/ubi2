import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  type Address,
  type Hex,
  type TransactionReceipt,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { proofOfHumanityAbi } from "../app/abi/proofOfHumanity";
import { CHAINS } from "../app/config";
import { validateSponsoredMintBinding } from "../app/lib/sponsored-mint";
import { sponsorTransactionSpendWei } from "../app/lib/sponsor-budget";
import {
  readSponsoredMintEvidence,
  submitSponsoredMint,
  waitForSponsoredMintEvidence,
} from "../app/lib/server/sponsored-mint-executor";
import { serializeVoucher, type HumanityVoucher } from "../app/lib/voucher";
import { getSponsoredMintServerConfig } from "../app/server-config";

const EVIDENCE_SCHEMA = "poh-sponsored-mint-rehearsal-evidence" as const;

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function chainIdFromEnvironment(): number {
  const raw = required("POH_REHEARSAL_CHAIN_ID");
  if (!/^[1-9][0-9]*$/.test(raw)) throw new Error("POH_REHEARSAL_CHAIN_ID must be a positive integer.");
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) throw new Error("POH_REHEARSAL_CHAIN_ID is too large.");
  return value;
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function optionalTransactionHash(): Hex | null {
  const value = process.env.POH_REHEARSAL_TRANSACTION_HASH?.trim();
  if (!value) return null;
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("POH_REHEARSAL_TRANSACTION_HASH must be a 32-byte transaction hash.");
  }
  return value as Hex;
}

function rollupL1Fee(receipt: TransactionReceipt): bigint {
  const value = (receipt as TransactionReceipt & { l1Fee?: bigint | Hex }).l1Fee;
  if (typeof value === "bigint") return value;
  if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) return BigInt(value);
  return 0n;
}

async function main(): Promise<void> {
  const chainId = chainIdFromEnvironment();
  const chain = CHAINS.find((candidate) => candidate.chainId === chainId);
  if (!chain || chain.network !== "testnet") {
    throw new Error("Rehearsal is restricted to a configured public testnet.");
  }
  const rawRecipient = required("POH_REHEARSAL_RECIPIENT");
  if (!isAddress(rawRecipient)) throw new Error("POH_REHEARSAL_RECIPIENT must be an EVM address.");
  const recipient = getAddress(rawRecipient);
  const nullifier = BigInt(required("POH_REHEARSAL_NULLIFIER"));
  if (nullifier <= 0n) throw new Error("POH_REHEARSAL_NULLIFIER must be positive.");
  const signature = required("POH_REHEARSAL_VOUCHER_SIGNATURE") as Hex;
  const voucherEpoch = Number(required("POH_REHEARSAL_EPOCH"));
  if (!Number.isSafeInteger(voucherEpoch) || voucherEpoch < 0 || voucherEpoch > 0xffff_ffff) {
    throw new Error("POH_REHEARSAL_EPOCH must be a uint32 integer.");
  }
  const recoveryHash = optionalTransactionHash();
  const config = getSponsoredMintServerConfig();
  if (!config) throw new Error("Testnet sponsorship is disabled.");
  if (config.enabledChainIds.length !== 1 || config.enabledChainIds[0] !== chainId) {
    throw new Error("Rehearsal requires an exact one-testnet sponsor allowlist.");
  }

  const account = privateKeyToAccount(config.privateKey);
  const client = createPublicClient({ transport: http(chain.rpcUrl, { retryCount: 1, timeout: 15_000 }) });
  const recoveryReceipt = recoveryHash ? await client.getTransactionReceipt({ hash: recoveryHash }) : null;
  const preflightBlockNumber = recoveryReceipt ? recoveryReceipt.blockNumber - 1n : undefined;
  const block = preflightBlockNumber === undefined ? {} : { blockNumber: preflightBlockNumber };
  const [rpcChainId, currentEpoch, issuer, owner, recipientBalanceBefore, recipientNonceBefore,
    recipientCodeBefore, credentialBalanceBefore, sponsorBalanceBefore] = await Promise.all([
    client.getChainId(),
    client.readContract({ address: chain.pohAddress, abi: proofOfHumanityAbi, functionName: "currentEpoch" }),
    client.readContract({ address: chain.pohAddress, abi: proofOfHumanityAbi, functionName: "issuer" }),
    client.readContract({ address: chain.pohAddress, abi: proofOfHumanityAbi, functionName: "owner" }),
    client.getBalance({ address: recipient, ...block }),
    client.getTransactionCount({ address: recipient, ...block }),
    client.getBytecode({ address: recipient, ...block }),
    client.readContract({
      address: chain.pohAddress,
      abi: proofOfHumanityAbi,
      functionName: "balanceOf",
      args: [recipient],
      ...block,
    }),
    client.getBalance({ address: account.address, ...block }),
  ]);
  if (rpcChainId !== chainId) throw new Error(`RPC returned chain ${rpcChainId}, expected ${chainId}.`);
  if (voucherEpoch !== currentEpoch && !recoveryHash) {
    throw new Error("Voucher epoch changed during rehearsal preflight; retry with a fresh signature.");
  }
  if (
    sameAddress(account.address, recipient) ||
    sameAddress(account.address, issuer) ||
    sameAddress(account.address, owner)
  ) {
    throw new Error("Sponsor overlaps recipient, issuer, or owner.");
  }
  if (
    recipientBalanceBefore !== 0n ||
    recipientNonceBefore !== 0 ||
    (recipientCodeBefore !== undefined && recipientCodeBefore !== "0x") ||
    credentialBalanceBefore !== 0n
  ) {
    throw new Error("Recipient is not a fresh, unfunded credential account.");
  }

  const voucher: HumanityVoucher = { to: recipient, nullifier, epoch: voucherEpoch };
  const serialized = serializeVoucher(voucher);
  const boundVoucher = validateSponsoredMintBinding({
    capabilityAddress: recipient,
    chain,
    signed: {
      chainId,
      name: chain.name,
      pohAddress: chain.pohAddress,
      voucher: serialized,
      signature,
    },
    proof: { nullifier: serialized.nullifier, epoch: serialized.epoch },
  });
  const execution = { chain, voucher: boundVoucher, signature, config };
  const submitted = recoveryHash
    ? { transactionHash: recoveryHash, submittedAt: Date.now() }
    : await submitSponsoredMint(execution);
  let evidence;
  try {
    evidence = recoveryHash
      ? await readSponsoredMintEvidence(execution, submitted.transactionHash)
      : await waitForSponsoredMintEvidence(execution, submitted.transactionHash);
  } catch (error) {
    const message = error instanceof Error ? error.message : "receipt verification unavailable";
    process.stdout.write(`${JSON.stringify({
      schema: EVIDENCE_SCHEMA,
      version: 1,
      status: "submitted",
      chainId,
      contract: chain.pohAddress,
      sponsor: account.address,
      recipient,
      transactionHash: submitted.transactionHash,
      recoverableError: message,
    }, null, 2)}\n`);
    process.exitCode = 2;
    return;
  }
  if (!evidence) {
    process.stdout.write(`${JSON.stringify({
      schema: EVIDENCE_SCHEMA,
      version: 1,
      status: "submitted",
      chainId,
      contract: chain.pohAddress,
      sponsor: account.address,
      recipient,
      transactionHash: submitted.transactionHash,
      recoverableError: "Transaction is not yet confirmed; retry with POH_REHEARSAL_TRANSACTION_HASH.",
    }, null, 2)}\n`);
    process.exitCode = 2;
    return;
  }
  const receipt = recoveryReceipt ?? await client.getTransactionReceipt({ hash: submitted.transactionHash });
  const [recipientBalanceAfter, recipientNonceAfter, credentialBalanceAfter, sponsorBalanceAfter] =
    await Promise.all([
      client.getBalance({ address: recipient, blockNumber: receipt.blockNumber }),
      client.getTransactionCount({ address: recipient, blockNumber: receipt.blockNumber }),
      client.readContract({
        address: chain.pohAddress,
        abi: proofOfHumanityAbi,
        functionName: "balanceOf",
        args: [recipient],
        blockNumber: receipt.blockNumber,
      }),
      client.getBalance({ address: account.address, blockNumber: receipt.blockNumber }),
    ]);
  if (recipientBalanceAfter !== 0n || recipientNonceAfter !== 0 || credentialBalanceAfter !== 1n) {
    throw new Error("Post-state does not prove a gasless mint to the unfunded recipient.");
  }

  const report = {
    schema: EVIDENCE_SCHEMA,
    version: 1,
    claim: "Live-chain sponsor-path rehearsal; not evidence of a human passport scan.",
    voucherSource: required("POH_REHEARSAL_VOUCHER_SOURCE"),
    mainnetEnabled: false,
    recoveryMode: recoveryHash !== null,
    voucherEpoch,
    chainId,
    chainName: chain.name,
    contract: chain.pohAddress,
    sponsor: account.address,
    issuer: issuer as Address,
    owner: owner as Address,
    recipient,
    preflight: {
      blockNumber: preflightBlockNumber?.toString() ?? "latest-before-submission",
      recipientBalanceWei: recipientBalanceBefore.toString(),
      recipientNonce: recipientNonceBefore,
      recipientCode: recipientCodeBefore ?? "0x",
      recipientCredentialBalance: credentialBalanceBefore.toString(),
      sponsorBalanceWei: sponsorBalanceBefore.toString(),
      rolesDistinct: true,
      accountVoucherBindingValidated: true,
    },
    receipt: evidence,
    postState: {
      blockNumber: receipt.blockNumber.toString(),
      recipientBalanceWei: recipientBalanceAfter.toString(),
      recipientNonce: recipientNonceAfter,
      recipientCredentialBalance: credentialBalanceAfter.toString(),
      sponsorBalanceWei: sponsorBalanceAfter.toString(),
      sponsorSpendWei: (sponsorBalanceBefore - sponsorBalanceAfter).toString(),
      receiptGasCostWei: sponsorTransactionSpendWei({
        gasUsed: receipt.gasUsed,
        effectiveGasPrice: receipt.effectiveGasPrice,
        l1FeeWei: rollupL1Fee(receipt),
      }).toString(),
      rollupL1FeeWei: rollupL1Fee(receipt).toString(),
    },
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown rehearsal failure";
  process.stderr.write(`sponsored mint rehearsal failed: ${message}\n`);
  process.exitCode = 1;
});
