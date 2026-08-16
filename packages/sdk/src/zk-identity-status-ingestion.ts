/**
 * Finalized EVM ingestion for the deterministic packed-status builder.
 *
 * The reader is intentionally narrow and mockable. The default viem adapter
 * uses the RPC's `finalized` tag; unsupported finality fails closed rather
 * than silently substituting `latest` or an arbitrary confirmation count.
 */
import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  isHex,
  size,
  type Address,
  type Hex,
} from "viem";
import {
  ZK_IDENTITY_MAX_NEXT_STATUS_ID,
  type ZkIdentityStatusSourceTranscript,
} from "./zk-identity-status-snapshot";

export const ZK_IDENTITY_FINALIZED_INGESTION_MAX_BLOCKS = 512n;
export const ZK_IDENTITY_FINALIZED_INGESTION_RPC_CONCURRENCY = 16;

export const zkIdentityCredentialAllocatedEvent = {
  type: "event",
  name: "CredentialAllocated",
  anonymous: false,
  inputs: [
    { name: "issuerKeyId", type: "bytes32", indexed: true },
    { name: "statusId", type: "uint32", indexed: true },
    { name: "credentialCommitment", type: "uint256", indexed: true },
    { name: "issuedAtEpoch", type: "uint32", indexed: false },
  ],
} as const;

export interface ZkIdentityFinalizedBlockHeader {
  number: bigint;
  hash: Hex;
  parentHash: Hex;
}

export interface ZkIdentityCredentialAllocatedLog {
  blockNumber: bigint;
  blockHash: Hex;
  logIndex: number;
  issuerKeyId: Hex;
  statusId: number;
}

export interface ZkIdentityFinalizedRpcReader {
  getChainId(): Promise<number>;
  getFinalizedBlock(): Promise<ZkIdentityFinalizedBlockHeader>;
  getBlock(blockNumber: bigint): Promise<ZkIdentityFinalizedBlockHeader>;
  getCredentialAllocatedLogs(input: {
    registry: Address;
    issuerKeyId: Hex;
    fromBlock: bigint;
    toBlock: bigint;
  }): Promise<readonly ZkIdentityCredentialAllocatedLog[]>;
}

export interface CollectZkIdentityFinalizedStatusInput {
  reader: ZkIdentityFinalizedRpcReader;
  chainId: number;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  anchor: ZkIdentityFinalizedBlockHeader;
  /** Exact allocation counter restored from the durable builder checkpoint. */
  expectedNextStatusId: bigint;
}

function positiveChainId(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error("packed-status ingestion chain id must be a positive safe integer");
  }
  return value;
}

function canonicalAddress(value: unknown): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error("packed-status ingestion registry must be a non-zero EVM address");
  }
  return getAddress(value).toLowerCase() as Address;
}

function canonicalBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function canonicalHeader(
  value: ZkIdentityFinalizedBlockHeader,
  label: string,
): ZkIdentityFinalizedBlockHeader {
  if (typeof value.number !== "bigint" || value.number < 0n) {
    throw new Error(`${label} number must be a non-negative bigint`);
  }
  const hash = canonicalBytes32(value.hash, `${label} hash`);
  if (BigInt(hash) === 0n) throw new Error(`${label} hash must not be zero`);
  return {
    number: value.number,
    hash,
    parentHash: canonicalBytes32(value.parentHash, `${label} parent hash`),
  };
}

/** Default finalized-tag reader for an EVM JSON-RPC endpoint. */
export function createZkIdentityFinalizedViemReader(
  rpcUrl: string,
): ZkIdentityFinalizedRpcReader {
  if (typeof rpcUrl !== "string" || rpcUrl.length === 0) {
    throw new Error("packed-status RPC URL is required");
  }
  const client = createPublicClient({ transport: http(rpcUrl) });
  const normalizeBlock = (block: {
    number: bigint;
    hash: Hex;
    parentHash: Hex;
  }): ZkIdentityFinalizedBlockHeader => ({
    number: block.number,
    hash: block.hash,
    parentHash: block.parentHash,
  });
  return {
    getChainId: () => client.getChainId(),
    getFinalizedBlock: async () => normalizeBlock(await client.getBlock({ blockTag: "finalized" })),
    getBlock: async (blockNumber) => normalizeBlock(await client.getBlock({ blockNumber })),
    getCredentialAllocatedLogs: async ({ registry, issuerKeyId, fromBlock, toBlock }) => {
      const logs = await client.getLogs({
        address: registry,
        event: zkIdentityCredentialAllocatedEvent,
        args: { issuerKeyId },
        fromBlock,
        toBlock,
      });
      return logs.map((log) => {
        if (
          log.blockNumber === null ||
          log.blockHash === null ||
          log.logIndex === null ||
          log.args.issuerKeyId === undefined ||
          log.args.statusId === undefined
        ) {
          throw new Error("finalized allocation log is missing mined metadata");
        }
        return {
          blockNumber: log.blockNumber,
          blockHash: log.blockHash,
          logIndex: log.logIndex,
          issuerKeyId: log.args.issuerKeyId,
          statusId: log.args.statusId,
        };
      });
    },
  };
}

/**
 * Collect one bounded finalized batch, including empty blocks, for strict
 * parent-hash replay by the Rust snapshot builder.
 */
export async function collectZkIdentityFinalizedStatusTranscript(
  input: CollectZkIdentityFinalizedStatusInput,
): Promise<ZkIdentityStatusSourceTranscript> {
  const chainId = positiveChainId(input.chainId);
  const issuanceRegistry = canonicalAddress(input.issuanceRegistry);
  const issuerKeyId = canonicalBytes32(input.issuerKeyId, "packed-status ingestion issuer key id");
  if (BigInt(issuerKeyId) === 0n) throw new Error("packed-status issuer key id must not be zero");
  if (
    typeof input.expectedNextStatusId !== "bigint" ||
    input.expectedNextStatusId < 1n ||
    input.expectedNextStatusId > ZK_IDENTITY_MAX_NEXT_STATUS_ID
  ) {
    throw new Error("packed-status expected next status id is outside the uint32 allocation range");
  }
  const anchor = canonicalHeader(input.anchor, "packed-status anchor");
  if ((await input.reader.getChainId()) !== chainId) {
    throw new Error("packed-status RPC returned the wrong chain id");
  }
  const finalized = canonicalHeader(
    await input.reader.getFinalizedBlock(),
    "packed-status finalized block",
  );
  if (finalized.number < anchor.number) {
    throw new Error("packed-status finalized tip is behind the durable checkpoint");
  }
  const blockCount = finalized.number - anchor.number;
  if (blockCount > ZK_IDENTITY_FINALIZED_INGESTION_MAX_BLOCKS) {
    throw new Error("packed-status finalized batch exceeds the bounded checkpoint interval");
  }
  if (blockCount === 0n) {
    if (finalized.hash !== anchor.hash) {
      throw new Error("packed-status finalized tip conflicts with the durable checkpoint");
    }
    return {
      schema: "org.proofofhumanity.v2-packed-status-source/1",
      chainId: chainId.toString(),
      issuanceRegistry,
      issuerKeyId,
      anchor: wireHeader(anchor),
      blocks: [],
    };
  }

  const numbers = Array.from(
    { length: Number(blockCount) },
    (_, index) => anchor.number + BigInt(index + 1),
  );
  const headers: ZkIdentityFinalizedBlockHeader[] = [];
  for (
    let offset = 0;
    offset < numbers.length;
    offset += ZK_IDENTITY_FINALIZED_INGESTION_RPC_CONCURRENCY
  ) {
    const batch = numbers.slice(
      offset,
      offset + ZK_IDENTITY_FINALIZED_INGESTION_RPC_CONCURRENCY,
    );
    headers.push(
      ...(await Promise.all(
        batch.map(async (number) =>
          canonicalHeader(await input.reader.getBlock(number), "packed-status block"),
        ),
      )),
    );
  }
  let expectedParent = anchor.hash;
  for (const [index, header] of headers.entries()) {
    if (header.number !== numbers[index] || header.parentHash !== expectedParent) {
      throw new Error("packed-status RPC returned a non-contiguous finalized branch");
    }
    expectedParent = header.hash;
  }
  const last = headers.at(-1);
  if (last === undefined || last.number !== finalized.number || last.hash !== finalized.hash) {
    throw new Error("packed-status finalized target does not match the fetched branch");
  }

  const logs = await input.reader.getCredentialAllocatedLogs({
    registry: issuanceRegistry,
    issuerKeyId,
    fromBlock: numbers[0],
    toBlock: finalized.number,
  });
  const byBlock = new Map<bigint, ZkIdentityStatusSourceTranscript["blocks"][number]["events"]>();
  let nextStatusId = input.expectedNextStatusId;
  let previousBlock = -1n;
  let previousLogIndex = -1;
  for (const log of logs) {
    const blockHash = canonicalBytes32(log.blockHash, "packed-status allocation block hash");
    const logIssuerKeyId = canonicalBytes32(
      log.issuerKeyId,
      "packed-status allocation issuer key id",
    );
    if (
      log.blockNumber < numbers[0] ||
      log.blockNumber > finalized.number ||
      !Number.isSafeInteger(log.logIndex) ||
      log.logIndex < 0 ||
      (log.blockNumber < previousBlock ||
        (log.blockNumber === previousBlock && log.logIndex <= previousLogIndex))
    ) {
      throw new Error("packed-status allocation logs are missing or out of canonical order");
    }
    const header = headers[Number(log.blockNumber - numbers[0])];
    if (header === undefined || header.hash !== blockHash || logIssuerKeyId !== issuerKeyId) {
      throw new Error("packed-status allocation log does not match the finalized branch");
    }
    if (
      !Number.isInteger(log.statusId) ||
      log.statusId <= 0 ||
      BigInt(log.statusId) !== nextStatusId ||
      nextStatusId > 0xffff_ffffn
    ) {
      throw new Error("packed-status allocation IDs are not dense at the checkpoint watermark");
    }
    const events = byBlock.get(log.blockNumber) ?? [];
    events.push({
      kind: "credential-allocated",
      logIndex: log.logIndex,
      issuerKeyId,
      statusId: log.statusId,
    });
    byBlock.set(log.blockNumber, events);
    nextStatusId += 1n;
    previousBlock = log.blockNumber;
    previousLogIndex = log.logIndex;
  }

  return {
    schema: "org.proofofhumanity.v2-packed-status-source/1",
    chainId: chainId.toString(),
    issuanceRegistry,
    issuerKeyId,
    anchor: wireHeader(anchor),
    blocks: headers.map((header) => ({
      ...wireHeader(header),
      events: byBlock.get(header.number) ?? [],
    })),
  };
}

function wireHeader(header: ZkIdentityFinalizedBlockHeader) {
  return {
    number: header.number.toString(),
    hash: header.hash,
    parentHash: header.parentHash,
  };
}

export function serializeZkIdentityStatusSourceTranscript(
  transcript: ZkIdentityStatusSourceTranscript,
): string {
  return JSON.stringify(transcript);
}
