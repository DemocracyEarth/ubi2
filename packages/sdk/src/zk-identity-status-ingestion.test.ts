import assert from "node:assert/strict";
import type { Hex } from "viem";
import {
  collectZkIdentityFinalizedStatusTranscript,
  serializeZkIdentityStatusSourceTranscript,
  type ZkIdentityCredentialAllocatedLog,
  type ZkIdentityFinalizedBlockHeader,
  type ZkIdentityFinalizedRpcReader,
} from "./zk-identity-status-ingestion";

const hash = (byte: string) => `0x${byte.repeat(64)}` as Hex;
const issuerKeyId = hash("2");
const issuanceRegistry = "0x1111111111111111111111111111111111111111" as const;
const anchor: ZkIdentityFinalizedBlockHeader = {
  number: 100n,
  hash: hash("1"),
  parentHash: hash("0"),
};
const blocks = new Map<bigint, ZkIdentityFinalizedBlockHeader>([
  [101n, { number: 101n, hash: hash("3"), parentHash: hash("1") }],
  [102n, { number: 102n, hash: hash("4"), parentHash: hash("3") }],
  [103n, { number: 103n, hash: hash("5"), parentHash: hash("4") }],
]);
const logs: ZkIdentityCredentialAllocatedLog[] = [
  {
    blockNumber: 101n,
    blockHash: hash("3"),
    logIndex: 4,
    issuerKeyId,
    statusId: 1,
  },
  {
    blockNumber: 102n,
    blockHash: hash("4"),
    logIndex: 2,
    issuerKeyId,
    statusId: 2,
  },
];

const baseReader: ZkIdentityFinalizedRpcReader = {
  getChainId: async () => 84_532,
  getFinalizedBlock: async () => blocks.get(103n)!,
  getBlock: async (blockNumber) => {
    const block = blocks.get(blockNumber);
    if (block === undefined) throw new Error("missing fixture block");
    return block;
  },
  getCredentialAllocatedLogs: async () => logs,
};
const reader = (
  overrides: Partial<ZkIdentityFinalizedRpcReader> = {},
): ZkIdentityFinalizedRpcReader => ({ ...baseReader, ...overrides });

const transcript = await collectZkIdentityFinalizedStatusTranscript({
  reader: reader(),
  chainId: 84_532,
  issuanceRegistry,
  issuerKeyId,
  anchor,
  expectedNextStatusId: 1n,
});
assert.equal(transcript.blocks.length, 3);
assert.deepEqual(
  transcript.blocks.map((block) => block.events.length),
  [1, 1, 0],
  "empty finalized blocks remain in the parent-hash transcript",
);
assert.equal(transcript.blocks[0]?.events[0]?.kind, "credential-allocated");
assert.equal(transcript.blocks[1]?.events[0]?.statusId, 2);
assert.equal(serializeZkIdentityStatusSourceTranscript(transcript), JSON.stringify(transcript));

await assert.rejects(
  collectZkIdentityFinalizedStatusTranscript({
    reader: reader({ getChainId: async () => 1 }),
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    anchor,
    expectedNextStatusId: 1n,
  }),
  /wrong chain/u,
);
await assert.rejects(
  collectZkIdentityFinalizedStatusTranscript({
    reader: reader({
      getCredentialAllocatedLogs: async () => [{ ...logs[0]!, statusId: 2 }],
    }),
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    anchor,
    expectedNextStatusId: 1n,
  }),
  /not dense/u,
);
await assert.rejects(
  collectZkIdentityFinalizedStatusTranscript({
    reader: reader({
      getCredentialAllocatedLogs: async () => [{ ...logs[0]!, blockHash: hash("9") }],
    }),
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    anchor,
    expectedNextStatusId: 1n,
  }),
  /does not match the finalized branch/u,
);
await assert.rejects(
  collectZkIdentityFinalizedStatusTranscript({
    reader: reader({ getCredentialAllocatedLogs: async () => [logs[1]!, logs[0]!] }),
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    anchor,
    expectedNextStatusId: 2n,
  }),
  /missing or out of canonical order/u,
);
await assert.rejects(
  collectZkIdentityFinalizedStatusTranscript({
    reader: reader({
      getBlock: async (number) =>
        number === 102n
          ? { number, hash: hash("4"), parentHash: hash("9") }
          : baseReader.getBlock(number),
    }),
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    anchor,
    expectedNextStatusId: 1n,
  }),
  /non-contiguous/u,
);
await assert.rejects(
  collectZkIdentityFinalizedStatusTranscript({
    reader: reader({
      getFinalizedBlock: async () => ({
        number: 613n,
        hash: hash("6"),
        parentHash: hash("5"),
      }),
    }),
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    anchor,
    expectedNextStatusId: 1n,
  }),
  /bounded checkpoint interval/u,
);

const noChange = await collectZkIdentityFinalizedStatusTranscript({
  reader: reader({ getFinalizedBlock: async () => anchor }),
  chainId: 84_532,
  issuanceRegistry,
  issuerKeyId,
  anchor,
  expectedNextStatusId: 3n,
});
assert.deepEqual(noChange.blocks, []);

console.log("zk packed-status ingestion: finalized continuity + bounded replay PASS");
