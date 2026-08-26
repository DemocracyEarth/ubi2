import { readFile, rename, writeFile } from "node:fs/promises";
import { getAddress, isAddress, createPublicClient, http, type Address, type Hex } from "viem";
import { CHAINS } from "../app/config";
import { evaluateSponsorBudget, sponsorTransactionSpendWei } from "../app/lib/sponsor-budget";

const STATE_SCHEMA = "poh-sponsor-monitor-state" as const;
const REPORT_SCHEMA = "poh-sponsor-monitor-report" as const;

interface MonitorState {
  schema: typeof STATE_SCHEMA;
  version: 1;
  chainId: number;
  sponsor: Address;
  throughBlock: string;
  utcDay: string;
  dailySpendWei: string;
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function positiveBigInt(name: string): bigint {
  const value = required(name);
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${name} must be a positive integer.`);
  return BigInt(value);
}

function positiveInteger(name: string, fallback?: number): number {
  const raw = process.env[name]?.trim();
  if (!raw && fallback !== undefined) return fallback;
  if (!raw || !/^[1-9][0-9]*$/.test(raw)) throw new Error(`${name} must be a positive integer.`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) throw new Error(`${name} is too large.`);
  return value;
}

function utcDay(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function rollupL1Fee(receipt: unknown): bigint {
  const value = (receipt as { l1Fee?: bigint | Hex }).l1Fee;
  if (typeof value === "bigint") return value;
  if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) return BigInt(value);
  return 0n;
}

async function loadState(path: string): Promise<MonitorState | null> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as Partial<MonitorState>;
    if (
      parsed.schema !== STATE_SCHEMA ||
      parsed.version !== 1 ||
      typeof parsed.chainId !== "number" ||
      typeof parsed.sponsor !== "string" ||
      typeof parsed.throughBlock !== "string" ||
      typeof parsed.utcDay !== "string" ||
      typeof parsed.dailySpendWei !== "string"
    ) {
      throw new Error("monitor state has an invalid shape");
    }
    return parsed as MonitorState;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

async function storeState(path: string, state: MonitorState): Promise<void> {
  const temporary = `${path}.tmp`;
  await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporary, path);
}

async function main(): Promise<void> {
  const chainId = positiveInteger("POH_SPONSOR_MONITOR_CHAIN_ID");
  const chain = CHAINS.find((candidate) => candidate.chainId === chainId);
  if (!chain || chain.network !== "testnet") {
    throw new Error("POH_SPONSOR_MONITOR_CHAIN_ID must select a configured public testnet.");
  }
  const rawSponsor = required("POH_SPONSOR_MONITOR_ADDRESS");
  if (!isAddress(rawSponsor)) throw new Error("POH_SPONSOR_MONITOR_ADDRESS must be an EVM address.");
  const sponsor = getAddress(rawSponsor);
  const statePath = required("POH_SPONSOR_MONITOR_STATE_FILE");
  const maximumBlocks = positiveInteger("POH_SPONSOR_MONITOR_MAX_BLOCKS", 500);
  const policy = {
    minimumReserveWei: positiveBigInt("POH_SPONSOR_MONITOR_MIN_RESERVE_WEI"),
    maximumBalanceWei: positiveBigInt("POH_SPONSOR_MONITOR_MAX_BALANCE_WEI"),
    dailySpendLimitWei: positiveBigInt("POH_SPONSOR_MONITOR_DAILY_SPEND_LIMIT_WEI"),
  };
  if (policy.minimumReserveWei >= policy.maximumBalanceWei) {
    throw new Error("Sponsor minimum reserve must be lower than its maximum balance cap.");
  }

  const client = createPublicClient({ transport: http(chain.rpcUrl, { retryCount: 1, timeout: 15_000 }) });
  const [rpcChainId, latestBlock, balanceWei, nonce] = await Promise.all([
    client.getChainId(),
    client.getBlockNumber(),
    client.getBalance({ address: sponsor }),
    client.getTransactionCount({ address: sponsor }),
  ]);
  if (rpcChainId !== chainId) throw new Error(`RPC returned chain ${rpcChainId}, expected ${chainId}.`);

  const prior = await loadState(statePath);
  if (prior && (prior.chainId !== chainId || !sameAddress(prior.sponsor, sponsor))) {
    throw new Error("Monitor state belongs to a different chain or sponsor account.");
  }
  const day = utcDay();
  let dailySpendWei = prior?.utcDay === day ? BigInt(prior.dailySpendWei) : 0n;
  let transactionsObserved = 0;
  const transactionHashes: Hex[] = [];
  const firstBlock = prior
    ? BigInt(prior.throughBlock) + 1n
    : positiveBigInt("POH_SPONSOR_MONITOR_START_BLOCK");
  if (!prior && firstBlock > latestBlock) {
    throw new Error("POH_SPONSOR_MONITOR_START_BLOCK is ahead of the RPC head.");
  }
  const blockCount = latestBlock >= firstBlock ? latestBlock - firstBlock + 1n : 0n;
  if (blockCount > BigInt(maximumBlocks)) {
    throw new Error(
      `Monitor gap is ${blockCount} blocks; refusing to skip spend history above POH_SPONSOR_MONITOR_MAX_BLOCKS.`,
    );
  }

  for (let blockNumber = firstBlock; blockNumber <= latestBlock; blockNumber += 1n) {
    const block = await client.getBlock({ blockNumber, includeTransactions: true });
    for (const transaction of block.transactions) {
      if (typeof transaction === "string" || !sameAddress(transaction.from, sponsor)) continue;
      const receipt = await client.getTransactionReceipt({ hash: transaction.hash });
      if (utcDay(new Date(Number(block.timestamp) * 1_000)) === day) {
        dailySpendWei += sponsorTransactionSpendWei({
          gasUsed: receipt.gasUsed,
          effectiveGasPrice: receipt.effectiveGasPrice,
          l1FeeWei: rollupL1Fee(receipt),
          successfulValueWei: receipt.status === "success" ? transaction.value : 0n,
        });
      }
      transactionsObserved += 1;
      transactionHashes.push(transaction.hash);
    }
  }

  const state: MonitorState = {
    schema: STATE_SCHEMA,
    version: 1,
    chainId,
    sponsor,
    throughBlock: latestBlock.toString(),
    utcDay: day,
    dailySpendWei: dailySpendWei.toString(),
  };
  await storeState(statePath, state);
  const alerts = evaluateSponsorBudget({ balanceWei, dailySpendWei }, policy);
  const report = {
    schema: REPORT_SCHEMA,
    version: 1,
    checkedAt: new Date().toISOString(),
    chainId,
    chainName: chain.name,
    sponsor,
    throughBlock: latestBlock.toString(),
    balanceWei: balanceWei.toString(),
    nonce,
    dailySpendWei: dailySpendWei.toString(),
    transactionsObserved,
    transactionHashes,
    policy: {
      minimumReserveWei: policy.minimumReserveWei.toString(),
      maximumBalanceWei: policy.maximumBalanceWei.toString(),
      dailySpendLimitWei: policy.dailySpendLimitWei.toString(),
    },
    alerts,
    ok: alerts.length === 0,
  };
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (alerts.length > 0) process.exitCode = 2;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown monitor failure";
  process.stderr.write(`sponsor monitor failed: ${message}\n`);
  process.exitCode = 1;
});
