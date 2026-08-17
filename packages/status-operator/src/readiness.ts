import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, mkdir, open, readFile, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import { zkIssuanceDomainHash } from "@ubi2/sdk";
import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  isHex,
  keccak256,
  parseAbi,
  size,
  type Address,
  type Hex,
} from "viem";
import { canonicalOperatorId } from "./artifact";
import {
  parseZkIdentityStatusFleetConfig,
  parseZkIdentityStatusOperatorConfig,
  type ZkIdentityStatusFleetConfig,
  type ZkIdentityStatusOperatorConfig,
} from "./config";

export const ZK_IDENTITY_STATUS_TESTNET_TRUST_RECORD_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-trust-record/1" as const;
export const ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_EVIDENCE_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-preflight-evidence/1" as const;
export const ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_REPORT_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-preflight-report/1" as const;

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;
const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const supportedNetworks = {
  "base-sepolia": 84_532,
  "ethereum-sepolia": 11_155_111,
  "celo-sepolia": 11_142_220,
  "robinhood-testnet": 46_630,
  "worldchain-sepolia": 4_801,
} as const;

type SupportedNetwork = keyof typeof supportedNetworks;

export interface ZkIdentityStatusTestnetTrustOperator {
  operatorId: string;
  hostId: string;
  volumeId: string;
  rpcProviderId: string;
  signerAddress: Address;
  baseUrl: string;
}

export interface ZkIdentityStatusTestnetTrustRecord {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_TRUST_RECORD_SCHEMA;
  network: SupportedNetwork;
  chainId: number;
  issuanceRegistry: Address;
  registryDeploymentTransaction: Hex;
  registryRuntimeCodeHash: Hex;
  deployerAddress: Address;
  ownerAddress: Address;
  issuerKeyId: Hex;
  statusPublisherAddress: Address;
  reviewedSourceCommit: string;
  builderSha256: Hex;
  castSha256: Hex;
  operators: ZkIdentityStatusTestnetTrustOperator[];
  fleetHostId: string;
  referenceRpcProviderId: string;
}

interface PublicOperatorConfiguration {
  operatorId: string;
  chainId: number;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  signerAddress: Address;
  builderSha256: Hex;
  castSha256: Hex;
  pollIntervalSeconds: number;
  listenHost: "127.0.0.1" | "::1";
  listenPort: number;
}

export interface ZkIdentityStatusTestnetPublicTopology {
  operators: PublicOperatorConfiguration[];
  fleet: {
    chainId: number;
    issuanceRegistry: Address;
    issuerKeyId: Hex;
    threshold: number;
    maxHeartbeatAgeSeconds: number;
    maxBlockLag: number;
    operators: ZkIdentityStatusFleetConfig["operators"];
  };
}

export interface ZkIdentityStatusTestnetRpcObservation {
  chainId: number;
  finalizedBlockNumber: string;
  finalizedBlockHash: Hex;
  registryRuntimeCodeHash: Hex;
  issuanceDomain: Hex;
  ownerAddress: Address;
  pendingOwnerAddress: Address;
  issuerKey: {
    registered: boolean;
    active: boolean;
    nextStatusId: string;
  };
  statusPublisher: {
    configuredCodeHash: Hex;
    runtimeCodeHash: Hex;
    registered: boolean;
    active: boolean;
  };
  registryDeployment: {
    transactionHash: Hex;
    blockNumber: string;
    blockHash: Hex;
    from: Address;
    contractAddress: Address | null;
    status: "success" | "reverted";
  };
}

export interface ZkIdentityStatusTestnetProviderObservation {
  providerId: string;
  observation: ZkIdentityStatusTestnetRpcObservation | null;
}

export type ZkIdentityStatusTestnetPreflightAlertCode =
  | "RPC_UNAVAILABLE"
  | "CHAIN_ID_MISMATCH"
  | "REGISTRY_BYTECODE_MISMATCH"
  | "REGISTRY_DEPLOYMENT_MISMATCH"
  | "REGISTRY_DEPLOYMENT_NOT_FINALIZED"
  | "OWNER_MISMATCH"
  | "OWNERSHIP_TRANSFER_PENDING"
  | "ISSUANCE_DOMAIN_MISMATCH"
  | "ISSUER_KEY_INACTIVE"
  | "STATUS_PUBLISHER_INACTIVE"
  | "STATUS_PUBLISHER_CODEHASH_MISMATCH"
  | "PROVIDER_STATE_DISAGREEMENT";

export interface ZkIdentityStatusTestnetPreflightReport {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_REPORT_SCHEMA;
  observedAt: string;
  ready: boolean;
  alerts: Array<{
    code: ZkIdentityStatusTestnetPreflightAlertCode;
    providerId: string | null;
  }>;
  externalChecksRequired: readonly [
    "HOST_VOLUME_PROVIDER_INDEPENDENCE",
    "SOURCE_AND_EXECUTABLE_HASHES_ON_HOSTS",
    "KEYSTORE_ADDRESS_AND_FILE_PERMISSIONS",
    "AUTHORITATIVE_EVIDENCE_TIMESTAMP",
  ];
}

export interface ZkIdentityStatusTestnetPreflightEvidence {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_EVIDENCE_SCHEMA;
  trustRecord: ZkIdentityStatusTestnetTrustRecord;
  topology: ZkIdentityStatusTestnetPublicTopology;
  providers: ZkIdentityStatusTestnetProviderObservation[];
  report: ZkIdentityStatusTestnetPreflightReport;
  evidenceSha256: Hex;
}

const trustRecordKeys = [
  "schema",
  "network",
  "chainId",
  "issuanceRegistry",
  "registryDeploymentTransaction",
  "registryRuntimeCodeHash",
  "deployerAddress",
  "ownerAddress",
  "issuerKeyId",
  "statusPublisherAddress",
  "reviewedSourceCommit",
  "builderSha256",
  "castSha256",
  "operators",
  "fleetHostId",
  "referenceRpcProviderId",
] as const;
const trustOperatorKeys = [
  "operatorId",
  "hostId",
  "volumeId",
  "rpcProviderId",
  "signerAddress",
  "baseUrl",
] as const;
const observationKeys = [
  "chainId",
  "finalizedBlockNumber",
  "finalizedBlockHash",
  "registryRuntimeCodeHash",
  "issuanceDomain",
  "ownerAddress",
  "pendingOwnerAddress",
  "issuerKey",
  "statusPublisher",
  "registryDeployment",
] as const;
const issuerKeyKeys = ["registered", "active", "nextStatusId"] as const;
const statusPublisherKeys = [
  "configuredCodeHash",
  "runtimeCodeHash",
  "registered",
  "active",
] as const;
const deploymentKeys = [
  "transactionHash",
  "blockNumber",
  "blockHash",
  "from",
  "contractAddress",
  "status",
] as const;
const evidenceKeys = [
  "schema",
  "trustRecord",
  "topology",
  "providers",
  "report",
  "evidenceSha256",
] as const;
const providerKeys = ["providerId", "observation"] as const;
const reportKeys = ["schema", "observedAt", "ready", "alerts", "externalChecksRequired"] as const;
const alertKeys = ["code", "providerId"] as const;
const topologyKeys = ["operators", "fleet"] as const;
const publicOperatorKeys = [
  "operatorId",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "signerAddress",
  "builderSha256",
  "castSha256",
  "pollIntervalSeconds",
  "listenHost",
  "listenPort",
] as const;
const publicFleetKeys = [
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "threshold",
  "maxHeartbeatAgeSeconds",
  "maxBlockLag",
  "operators",
] as const;

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

function label(value: unknown, description: string): string {
  if (typeof value !== "string" || !/^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/u.test(value)) {
    throw new Error(`${description} must be a canonical public label`);
  }
  return value;
}

function address(value: unknown, description: string, allowZero = false): Address {
  if (typeof value !== "string" || !isAddress(value) || (!allowZero && BigInt(value) === 0n)) {
    throw new Error(`${description} must be ${allowZero ? "an" : "a non-zero"} EVM address`);
  }
  return getAddress(value);
}

function bytes32(value: unknown, description: string, allowZero = false): Hex {
  if (
    typeof value !== "string" ||
    !isHex(value) ||
    size(value) !== 32 ||
    (!allowZero && BigInt(value) === 0n)
  ) {
    throw new Error(`${description} must be ${allowZero ? "" : "non-zero "}bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function decimal(value: unknown, description: string): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${description} must be a canonical decimal integer`);
  }
  return value;
}

function integer(
  value: unknown,
  description: string,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error(`${description} must be a bounded integer`);
  }
  return value;
}

function publicUrl(value: unknown, description: string): string {
  if (typeof value !== "string") throw new Error(`${description} must be a URL`);
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error(`${description} must be public HTTPS without credentials, query, or fragment`);
  }
  return parsed.toString().replace(/\/+$/u, "");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`);
  return `{${entries.join(",")}}`;
}

function sha256(value: unknown): Hex {
  return `0x${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function unique(values: readonly string[], description: string): void {
  if (new Set(values.map((value) => value.toLowerCase())).size !== values.length) {
    throw new Error(`${description} must be distinct`);
  }
}

export function parseZkIdentityStatusTestnetTrustRecord(
  value: unknown,
): ZkIdentityStatusTestnetTrustRecord {
  const candidate = object(value, "canonical testnet trust record");
  exactKeys(candidate, trustRecordKeys, "canonical testnet trust record");
  if (candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_TRUST_RECORD_SCHEMA) {
    throw new Error("unsupported canonical testnet trust record schema");
  }
  if (
    typeof candidate.network !== "string" ||
    !(candidate.network in supportedNetworks)
  ) {
    throw new Error("canonical testnet trust record network is unsupported");
  }
  const network = candidate.network as SupportedNetwork;
  if (candidate.chainId !== supportedNetworks[network]) {
    throw new Error("canonical testnet trust record network and chain id do not match");
  }
  if (!Array.isArray(candidate.operators) || candidate.operators.length !== 2) {
    throw new Error("canonical testnet trust record requires exactly two operators");
  }
  const operators = candidate.operators
    .map((value) => {
      const operator = object(value, "canonical testnet trust operator");
      exactKeys(operator, trustOperatorKeys, "canonical testnet trust operator");
      return {
        operatorId: canonicalOperatorId(operator.operatorId),
        hostId: label(operator.hostId, "canonical testnet operator host id"),
        volumeId: label(operator.volumeId, "canonical testnet operator volume id"),
        rpcProviderId: label(operator.rpcProviderId, "canonical testnet operator RPC provider id"),
        signerAddress: address(operator.signerAddress, "canonical testnet operator signer"),
        baseUrl: publicUrl(operator.baseUrl, "canonical testnet operator origin"),
      };
    })
    .sort((left, right) => left.operatorId.localeCompare(right.operatorId));
  unique(operators.map(({ operatorId }) => operatorId), "canonical testnet operator ids");
  unique(operators.map(({ hostId }) => hostId), "canonical testnet operator host ids");
  unique(operators.map(({ volumeId }) => volumeId), "canonical testnet operator volume ids");
  unique(operators.map(({ rpcProviderId }) => rpcProviderId), "canonical testnet operator RPC providers");
  unique(operators.map(({ signerAddress }) => signerAddress), "canonical testnet operator signers");
  unique(operators.map(({ baseUrl }) => baseUrl), "canonical testnet operator origins");

  const record: ZkIdentityStatusTestnetTrustRecord = {
    schema: ZK_IDENTITY_STATUS_TESTNET_TRUST_RECORD_SCHEMA,
    network,
    chainId: supportedNetworks[network],
    issuanceRegistry: address(candidate.issuanceRegistry, "canonical testnet issuance registry"),
    registryDeploymentTransaction: bytes32(
      candidate.registryDeploymentTransaction,
      "canonical testnet registry deployment transaction",
    ),
    registryRuntimeCodeHash: bytes32(
      candidate.registryRuntimeCodeHash,
      "canonical testnet registry runtime code hash",
    ),
    deployerAddress: address(candidate.deployerAddress, "canonical testnet deployer"),
    ownerAddress: address(candidate.ownerAddress, "canonical testnet registry owner"),
    issuerKeyId: bytes32(candidate.issuerKeyId, "canonical testnet issuer key id"),
    statusPublisherAddress: address(
      candidate.statusPublisherAddress,
      "canonical testnet status publisher",
    ),
    reviewedSourceCommit:
      typeof candidate.reviewedSourceCommit === "string" &&
      /^[0-9a-f]{40}$/u.test(candidate.reviewedSourceCommit)
        ? candidate.reviewedSourceCommit
        : (() => {
            throw new Error("canonical testnet reviewed source commit must be a full lowercase git SHA-1");
          })(),
    builderSha256: bytes32(candidate.builderSha256, "canonical testnet builder SHA-256"),
    castSha256: bytes32(candidate.castSha256, "canonical testnet cast SHA-256"),
    operators,
    fleetHostId: label(candidate.fleetHostId, "canonical testnet fleet host id"),
    referenceRpcProviderId: label(
      candidate.referenceRpcProviderId,
      "canonical testnet reference RPC provider id",
    ),
  };
  unique(
    [...operators.map(({ hostId }) => hostId), record.fleetHostId],
    "canonical testnet trust-path host ids",
  );
  unique(
    [...operators.map(({ rpcProviderId }) => rpcProviderId), record.referenceRpcProviderId],
    "canonical testnet trust-path RPC providers",
  );
  unique(
    [
      record.deployerAddress,
      record.ownerAddress,
      record.statusPublisherAddress,
      ...operators.map(({ signerAddress }) => signerAddress),
    ].filter((value, index, values) => {
      // A disposable testnet deployer may remain the intended testnet owner.
      return !(value === record.ownerAddress && value === record.deployerAddress && index === 1 && values[0] === value);
    }),
    "canonical testnet signing roles other than deployer/owner",
  );
  return record;
}

function publicOperator(config: ZkIdentityStatusOperatorConfig): PublicOperatorConfiguration {
  return {
    operatorId: config.operatorId,
    chainId: config.chainId,
    issuanceRegistry: config.issuanceRegistry,
    issuerKeyId: config.issuerKeyId,
    signerAddress: config.signerAddress,
    builderSha256: config.builderSha256,
    castSha256: config.castSha256,
    pollIntervalSeconds: config.pollIntervalSeconds,
    listenHost: config.listenHost,
    listenPort: config.listenPort,
  };
}

export function validateZkIdentityStatusTestnetTopology(input: {
  trustRecord: unknown;
  operatorConfigs: readonly unknown[];
  fleetConfig: unknown;
}): {
  trustRecord: ZkIdentityStatusTestnetTrustRecord;
  operatorConfigs: ZkIdentityStatusOperatorConfig[];
  fleetConfig: ZkIdentityStatusFleetConfig;
  publicTopology: ZkIdentityStatusTestnetPublicTopology;
} {
  const trustRecord = parseZkIdentityStatusTestnetTrustRecord(input.trustRecord);
  if (input.operatorConfigs.length !== 2) {
    throw new Error("canonical testnet topology requires exactly two operator configs");
  }
  const operatorConfigs = input.operatorConfigs
    .map(parseZkIdentityStatusOperatorConfig)
    .sort((left, right) => left.operatorId.localeCompare(right.operatorId));
  const fleetConfig = parseZkIdentityStatusFleetConfig(input.fleetConfig);
  if (fleetConfig.operators.length !== 2 || fleetConfig.threshold !== 2) {
    throw new Error("canonical testnet fleet must require both of exactly two operators");
  }
  unique(
    [...operatorConfigs.map(({ rpcUrl }) => rpcUrl), fleetConfig.referenceRpcUrl],
    "canonical testnet RPC URLs",
  );
  for (const [index, expected] of trustRecord.operators.entries()) {
    const operator = operatorConfigs[index];
    const fleetOperator = [...fleetConfig.operators]
      .sort((left, right) => left.operatorId.localeCompare(right.operatorId))[index];
    if (
      operator === undefined ||
      fleetOperator === undefined ||
      operator.operatorId !== expected.operatorId ||
      fleetOperator.operatorId !== expected.operatorId ||
      operator.signerAddress !== expected.signerAddress ||
      fleetOperator.signerAddress !== expected.signerAddress ||
      fleetOperator.baseUrl !== expected.baseUrl ||
      operator.builderSha256 !== trustRecord.builderSha256 ||
      operator.castSha256 !== trustRecord.castSha256
    ) {
      throw new Error("canonical testnet operator configuration does not match the trust record");
    }
    if (
      operator.chainId !== trustRecord.chainId ||
      operator.issuanceRegistry !== trustRecord.issuanceRegistry ||
      operator.issuerKeyId !== trustRecord.issuerKeyId
    ) {
      throw new Error("canonical testnet operator chain trust does not match the trust record");
    }
  }
  if (
    fleetConfig.chainId !== trustRecord.chainId ||
    fleetConfig.issuanceRegistry !== trustRecord.issuanceRegistry ||
    fleetConfig.issuerKeyId !== trustRecord.issuerKeyId
  ) {
    throw new Error("canonical testnet fleet chain trust does not match the trust record");
  }
  return {
    trustRecord,
    operatorConfigs,
    fleetConfig,
    publicTopology: {
      operators: operatorConfigs.map(publicOperator),
      fleet: {
        chainId: fleetConfig.chainId,
        issuanceRegistry: fleetConfig.issuanceRegistry,
        issuerKeyId: fleetConfig.issuerKeyId,
        threshold: fleetConfig.threshold,
        maxHeartbeatAgeSeconds: fleetConfig.maxHeartbeatAgeSeconds,
        maxBlockLag: fleetConfig.maxBlockLag,
        operators: [...fleetConfig.operators].sort((left, right) =>
          left.operatorId.localeCompare(right.operatorId),
        ),
      },
    },
  };
}

const registryAbi = parseAbi([
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function issuanceDomain() view returns (bytes32)",
  "function issuerKeys(bytes32) view returns (bool registered, bool active, uint64 nextStatusId)",
  "function statusPublishers(bytes32,address) view returns (bytes32 codehash, bool registered, bool active)",
]);

export interface ZkIdentityStatusTestnetRpcReader {
  getChainId(): Promise<number>;
  getFinalizedBlock(): Promise<{ number: bigint; hash: Hex }>;
  getCode(address: Address, blockNumber: bigint): Promise<Hex | undefined>;
  getOwner(registry: Address, blockNumber: bigint): Promise<Address>;
  getPendingOwner(registry: Address, blockNumber: bigint): Promise<Address>;
  getIssuanceDomain(registry: Address, blockNumber: bigint): Promise<Hex>;
  getIssuerKey(
    registry: Address,
    issuerKeyId: Hex,
    blockNumber: bigint,
  ): Promise<readonly [boolean, boolean, bigint]>;
  getStatusPublisher(
    registry: Address,
    issuerKeyId: Hex,
    publisher: Address,
    blockNumber: bigint,
  ): Promise<readonly [Hex, boolean, boolean]>;
  getDeploymentReceipt(transactionHash: Hex): Promise<{
    transactionHash: Hex;
    blockNumber: bigint;
    blockHash: Hex;
    from: Address;
    contractAddress: Address | null;
    status: "success" | "reverted";
  }>;
}

export function createZkIdentityStatusTestnetViemReader(
  rpcUrl: string,
  timeoutMs: number,
): ZkIdentityStatusTestnetRpcReader {
  const client = createPublicClient({ transport: http(rpcUrl, { timeout: timeoutMs }) });
  return {
    getChainId: () => client.getChainId(),
    getFinalizedBlock: async () => {
      const block = await client.getBlock({ blockTag: "finalized" });
      return { number: block.number, hash: block.hash };
    },
    getCode: (target, blockNumber) => client.getCode({ address: target, blockNumber }),
    getOwner: (registry, blockNumber) =>
      client.readContract({ address: registry, abi: registryAbi, functionName: "owner", blockNumber }),
    getPendingOwner: (registry, blockNumber) =>
      client.readContract({
        address: registry,
        abi: registryAbi,
        functionName: "pendingOwner",
        blockNumber,
      }),
    getIssuanceDomain: (registry, blockNumber) =>
      client.readContract({
        address: registry,
        abi: registryAbi,
        functionName: "issuanceDomain",
        blockNumber,
      }),
    getIssuerKey: (registry, issuerKeyId, blockNumber) =>
      client.readContract({
        address: registry,
        abi: registryAbi,
        functionName: "issuerKeys",
        args: [issuerKeyId],
        blockNumber,
      }),
    getStatusPublisher: (registry, issuerKeyId, publisher, blockNumber) =>
      client.readContract({
        address: registry,
        abi: registryAbi,
        functionName: "statusPublishers",
        args: [issuerKeyId, publisher],
        blockNumber,
      }),
    getDeploymentReceipt: async (transactionHash) => {
      const receipt = await client.getTransactionReceipt({ hash: transactionHash });
      return {
        transactionHash: receipt.transactionHash,
        blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash,
        from: receipt.from,
        contractAddress: receipt.contractAddress ?? null,
        status: receipt.status,
      };
    },
  };
}

function runtimeCodeHash(code: Hex | undefined): Hex {
  return code === undefined || code === "0x" ? ZERO_BYTES32 : keccak256(code);
}

export async function collectZkIdentityStatusTestnetRpcObservation(input: {
  trustRecord: ZkIdentityStatusTestnetTrustRecord;
  reader: ZkIdentityStatusTestnetRpcReader;
}): Promise<ZkIdentityStatusTestnetRpcObservation> {
  const { trustRecord, reader } = input;
  const [chainId, finalized] = await Promise.all([
    reader.getChainId(),
    reader.getFinalizedBlock(),
  ]);
  const [
    registryCode,
    publisherCode,
    ownerAddress,
    pendingOwnerAddress,
    issuanceDomain,
    issuerKey,
    statusPublisher,
    registryDeployment,
  ] = await Promise.all([
    reader.getCode(trustRecord.issuanceRegistry, finalized.number),
    reader.getCode(trustRecord.statusPublisherAddress, finalized.number),
    reader.getOwner(trustRecord.issuanceRegistry, finalized.number),
    reader.getPendingOwner(trustRecord.issuanceRegistry, finalized.number),
    reader.getIssuanceDomain(trustRecord.issuanceRegistry, finalized.number),
    reader.getIssuerKey(trustRecord.issuanceRegistry, trustRecord.issuerKeyId, finalized.number),
    reader.getStatusPublisher(
      trustRecord.issuanceRegistry,
      trustRecord.issuerKeyId,
      trustRecord.statusPublisherAddress,
      finalized.number,
    ),
    reader.getDeploymentReceipt(trustRecord.registryDeploymentTransaction),
  ]);
  return {
    chainId,
    finalizedBlockNumber: finalized.number.toString(),
    finalizedBlockHash: bytes32(finalized.hash, "canonical testnet finalized block hash"),
    registryRuntimeCodeHash: runtimeCodeHash(registryCode),
    issuanceDomain: bytes32(issuanceDomain, "canonical testnet issuance domain"),
    ownerAddress: address(ownerAddress, "canonical testnet observed owner"),
    pendingOwnerAddress: address(
      pendingOwnerAddress,
      "canonical testnet observed pending owner",
      true,
    ),
    issuerKey: {
      registered: issuerKey[0],
      active: issuerKey[1],
      nextStatusId: issuerKey[2].toString(),
    },
    statusPublisher: {
      configuredCodeHash: bytes32(
        statusPublisher[0],
        "canonical testnet configured publisher code hash",
        true,
      ),
      runtimeCodeHash: runtimeCodeHash(publisherCode),
      registered: statusPublisher[1],
      active: statusPublisher[2],
    },
    registryDeployment: {
      transactionHash: bytes32(
        registryDeployment.transactionHash,
        "canonical testnet observed deployment transaction",
      ),
      blockNumber: registryDeployment.blockNumber.toString(),
      blockHash: bytes32(
        registryDeployment.blockHash,
        "canonical testnet deployment block hash",
      ),
      from: address(registryDeployment.from, "canonical testnet observed deployer"),
      contractAddress:
        registryDeployment.contractAddress === null
          ? null
          : address(
              registryDeployment.contractAddress,
              "canonical testnet observed deployed registry",
            ),
      status: registryDeployment.status,
    },
  };
}

function alert(
  code: ZkIdentityStatusTestnetPreflightAlertCode,
  providerId: string | null,
): { code: ZkIdentityStatusTestnetPreflightAlertCode; providerId: string | null } {
  return { code, providerId };
}

function consensusState(observation: ZkIdentityStatusTestnetRpcObservation): unknown {
  return {
    registryRuntimeCodeHash: observation.registryRuntimeCodeHash,
    issuanceDomain: observation.issuanceDomain,
    ownerAddress: observation.ownerAddress,
    pendingOwnerAddress: observation.pendingOwnerAddress,
    issuerKey: observation.issuerKey,
    statusPublisher: observation.statusPublisher,
    registryDeployment: observation.registryDeployment,
  };
}

export function evaluateZkIdentityStatusTestnetPreflight(input: {
  trustRecord: ZkIdentityStatusTestnetTrustRecord;
  providers: readonly ZkIdentityStatusTestnetProviderObservation[];
  observedAt?: Date;
}): ZkIdentityStatusTestnetPreflightReport {
  const observedAt = (input.observedAt ?? new Date()).toISOString();
  const expectedProviderIds = [
    ...input.trustRecord.operators.map(({ rpcProviderId }) => rpcProviderId),
    input.trustRecord.referenceRpcProviderId,
  ];
  if (
    input.providers.length !== expectedProviderIds.length ||
    input.providers.some((provider, index) => provider.providerId !== expectedProviderIds[index])
  ) {
    throw new Error("canonical testnet provider observations do not match the trust record");
  }
  const alerts: ZkIdentityStatusTestnetPreflightReport["alerts"] = [];
  const expectedIssuanceDomain = zkIssuanceDomainHash({
    chainId: input.trustRecord.chainId,
    registry: input.trustRecord.issuanceRegistry,
  });
  const accepted: ZkIdentityStatusTestnetRpcObservation[] = [];
  for (const provider of input.providers) {
    const observation = provider.observation;
    if (observation === null) {
      alerts.push(alert("RPC_UNAVAILABLE", provider.providerId));
      continue;
    }
    accepted.push(observation);
    if (observation.chainId !== input.trustRecord.chainId) {
      alerts.push(alert("CHAIN_ID_MISMATCH", provider.providerId));
    }
    if (observation.registryRuntimeCodeHash !== input.trustRecord.registryRuntimeCodeHash) {
      alerts.push(alert("REGISTRY_BYTECODE_MISMATCH", provider.providerId));
    }
    const deployment = observation.registryDeployment;
    if (
      deployment.transactionHash !== input.trustRecord.registryDeploymentTransaction ||
      deployment.status !== "success" ||
      deployment.from !== input.trustRecord.deployerAddress ||
      deployment.contractAddress !== input.trustRecord.issuanceRegistry
    ) {
      alerts.push(alert("REGISTRY_DEPLOYMENT_MISMATCH", provider.providerId));
    }
    if (BigInt(deployment.blockNumber) > BigInt(observation.finalizedBlockNumber)) {
      alerts.push(alert("REGISTRY_DEPLOYMENT_NOT_FINALIZED", provider.providerId));
    }
    if (observation.ownerAddress !== input.trustRecord.ownerAddress) {
      alerts.push(alert("OWNER_MISMATCH", provider.providerId));
    }
    if (observation.pendingOwnerAddress !== ZERO_ADDRESS) {
      alerts.push(alert("OWNERSHIP_TRANSFER_PENDING", provider.providerId));
    }
    if (observation.issuanceDomain !== expectedIssuanceDomain) {
      alerts.push(alert("ISSUANCE_DOMAIN_MISMATCH", provider.providerId));
    }
    if (!observation.issuerKey.registered || !observation.issuerKey.active) {
      alerts.push(alert("ISSUER_KEY_INACTIVE", provider.providerId));
    }
    if (!observation.statusPublisher.registered || !observation.statusPublisher.active) {
      alerts.push(alert("STATUS_PUBLISHER_INACTIVE", provider.providerId));
    }
    if (
      observation.statusPublisher.configuredCodeHash !==
      observation.statusPublisher.runtimeCodeHash
    ) {
      alerts.push(alert("STATUS_PUBLISHER_CODEHASH_MISMATCH", provider.providerId));
    }
  }
  if (
    accepted.length > 1 &&
    accepted.slice(1).some(
      (observation) => canonicalJson(consensusState(observation)) !== canonicalJson(consensusState(accepted[0]!)),
    )
  ) {
    alerts.push(alert("PROVIDER_STATE_DISAGREEMENT", null));
  }
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_REPORT_SCHEMA,
    observedAt,
    ready: alerts.length === 0 && accepted.length === expectedProviderIds.length,
    alerts,
    externalChecksRequired: [
      "HOST_VOLUME_PROVIDER_INDEPENDENCE",
      "SOURCE_AND_EXECUTABLE_HASHES_ON_HOSTS",
      "KEYSTORE_ADDRESS_AND_FILE_PERMISSIONS",
      "AUTHORITATIVE_EVIDENCE_TIMESTAMP",
    ],
  };
}

function evidencePayload(
  value: Omit<ZkIdentityStatusTestnetPreflightEvidence, "evidenceSha256">,
): Omit<ZkIdentityStatusTestnetPreflightEvidence, "evidenceSha256"> {
  return {
    schema: value.schema,
    trustRecord: value.trustRecord,
    topology: value.topology,
    providers: value.providers,
    report: value.report,
  };
}

export function createZkIdentityStatusTestnetPreflightEvidence(input: {
  trustRecord: ZkIdentityStatusTestnetTrustRecord;
  publicTopology: ZkIdentityStatusTestnetPublicTopology;
  providers: ZkIdentityStatusTestnetProviderObservation[];
  observedAt?: Date;
}): ZkIdentityStatusTestnetPreflightEvidence {
  const payload = {
    schema: ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_EVIDENCE_SCHEMA,
    trustRecord: input.trustRecord,
    topology: input.publicTopology,
    providers: input.providers,
    report: evaluateZkIdentityStatusTestnetPreflight({
      trustRecord: input.trustRecord,
      providers: input.providers,
      observedAt: input.observedAt,
    }),
  } satisfies Omit<ZkIdentityStatusTestnetPreflightEvidence, "evidenceSha256">;
  return { ...payload, evidenceSha256: sha256(evidencePayload(payload)) };
}

function parseObservation(value: unknown): ZkIdentityStatusTestnetRpcObservation {
  const candidate = object(value, "canonical testnet RPC observation");
  exactKeys(candidate, observationKeys, "canonical testnet RPC observation");
  const issuerKey = object(candidate.issuerKey, "canonical testnet observed issuer key");
  const statusPublisher = object(
    candidate.statusPublisher,
    "canonical testnet observed status publisher",
  );
  const deployment = object(
    candidate.registryDeployment,
    "canonical testnet observed registry deployment",
  );
  exactKeys(issuerKey, issuerKeyKeys, "canonical testnet observed issuer key");
  exactKeys(statusPublisher, statusPublisherKeys, "canonical testnet observed status publisher");
  exactKeys(deployment, deploymentKeys, "canonical testnet observed registry deployment");
  if (
    typeof candidate.chainId !== "number" ||
    !Number.isSafeInteger(candidate.chainId) ||
    candidate.chainId <= 0 ||
    typeof issuerKey.registered !== "boolean" ||
    typeof issuerKey.active !== "boolean" ||
    typeof statusPublisher.registered !== "boolean" ||
    typeof statusPublisher.active !== "boolean" ||
    (deployment.status !== "success" && deployment.status !== "reverted")
  ) {
    throw new Error("canonical testnet RPC observation contains invalid state");
  }
  return {
    chainId: candidate.chainId,
    finalizedBlockNumber: decimal(
      candidate.finalizedBlockNumber,
      "canonical testnet finalized block number",
    ),
    finalizedBlockHash: bytes32(
      candidate.finalizedBlockHash,
      "canonical testnet finalized block hash",
    ),
    registryRuntimeCodeHash: bytes32(
      candidate.registryRuntimeCodeHash,
      "canonical testnet registry runtime code hash",
      true,
    ),
    issuanceDomain: bytes32(candidate.issuanceDomain, "canonical testnet issuance domain"),
    ownerAddress: address(candidate.ownerAddress, "canonical testnet observed owner"),
    pendingOwnerAddress: address(
      candidate.pendingOwnerAddress,
      "canonical testnet observed pending owner",
      true,
    ),
    issuerKey: {
      registered: issuerKey.registered,
      active: issuerKey.active,
      nextStatusId: decimal(issuerKey.nextStatusId, "canonical testnet next status id"),
    },
    statusPublisher: {
      configuredCodeHash: bytes32(
        statusPublisher.configuredCodeHash,
        "canonical testnet configured publisher code hash",
        true,
      ),
      runtimeCodeHash: bytes32(
        statusPublisher.runtimeCodeHash,
        "canonical testnet publisher runtime code hash",
        true,
      ),
      registered: statusPublisher.registered,
      active: statusPublisher.active,
    },
    registryDeployment: {
      transactionHash: bytes32(
        deployment.transactionHash,
        "canonical testnet deployment transaction",
      ),
      blockNumber: decimal(deployment.blockNumber, "canonical testnet deployment block number"),
      blockHash: bytes32(deployment.blockHash, "canonical testnet deployment block hash"),
      from: address(deployment.from, "canonical testnet observed deployer"),
      contractAddress:
        deployment.contractAddress === null
          ? null
          : address(deployment.contractAddress, "canonical testnet observed registry"),
      status: deployment.status,
    },
  };
}

function parseReport(value: unknown): ZkIdentityStatusTestnetPreflightReport {
  const candidate = object(value, "canonical testnet preflight report");
  exactKeys(candidate, reportKeys, "canonical testnet preflight report");
  if (
    candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_REPORT_SCHEMA ||
    typeof candidate.observedAt !== "string" ||
    typeof candidate.ready !== "boolean" ||
    !Array.isArray(candidate.alerts) ||
    !Array.isArray(candidate.externalChecksRequired)
  ) {
    throw new Error("canonical testnet preflight report is invalid");
  }
  const observedAt = new Date(candidate.observedAt);
  if (!Number.isFinite(observedAt.getTime()) || observedAt.toISOString() !== candidate.observedAt) {
    throw new Error("canonical testnet preflight observation time is not canonical");
  }
  const allowedCodes: readonly ZkIdentityStatusTestnetPreflightAlertCode[] = [
    "RPC_UNAVAILABLE",
    "CHAIN_ID_MISMATCH",
    "REGISTRY_BYTECODE_MISMATCH",
    "REGISTRY_DEPLOYMENT_MISMATCH",
    "REGISTRY_DEPLOYMENT_NOT_FINALIZED",
    "OWNER_MISMATCH",
    "OWNERSHIP_TRANSFER_PENDING",
    "ISSUANCE_DOMAIN_MISMATCH",
    "ISSUER_KEY_INACTIVE",
    "STATUS_PUBLISHER_INACTIVE",
    "STATUS_PUBLISHER_CODEHASH_MISMATCH",
    "PROVIDER_STATE_DISAGREEMENT",
  ];
  const alerts = candidate.alerts.map((value) => {
    const item = object(value, "canonical testnet preflight alert");
    exactKeys(item, alertKeys, "canonical testnet preflight alert");
    if (
      typeof item.code !== "string" ||
      !allowedCodes.includes(item.code as ZkIdentityStatusTestnetPreflightAlertCode) ||
      (item.providerId !== null && typeof item.providerId !== "string")
    ) {
      throw new Error("canonical testnet preflight alert is invalid");
    }
    return {
      code: item.code as ZkIdentityStatusTestnetPreflightAlertCode,
      providerId:
        item.providerId === null
          ? null
          : label(item.providerId, "canonical testnet preflight alert provider"),
    };
  });
  const externalChecksRequired = [
    "HOST_VOLUME_PROVIDER_INDEPENDENCE",
    "SOURCE_AND_EXECUTABLE_HASHES_ON_HOSTS",
    "KEYSTORE_ADDRESS_AND_FILE_PERMISSIONS",
    "AUTHORITATIVE_EVIDENCE_TIMESTAMP",
  ] as const;
  if (canonicalJson(candidate.externalChecksRequired) !== canonicalJson(externalChecksRequired)) {
    throw new Error("canonical testnet preflight external checks are invalid");
  }
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_REPORT_SCHEMA,
    observedAt: candidate.observedAt,
    ready: candidate.ready,
    alerts,
    externalChecksRequired,
  };
}

function parsePublicTopology(value: unknown): ZkIdentityStatusTestnetPublicTopology {
  const candidate = object(value, "canonical testnet public topology");
  exactKeys(candidate, topologyKeys, "canonical testnet public topology");
  if (!Array.isArray(candidate.operators) || candidate.operators.length !== 2) {
    throw new Error("canonical testnet public topology requires exactly two operators");
  }
  const operators = candidate.operators
    .map((value) => {
      const operator = object(value, "canonical testnet public operator");
      exactKeys(operator, publicOperatorKeys, "canonical testnet public operator");
      if (operator.listenHost !== "127.0.0.1" && operator.listenHost !== "::1") {
        throw new Error("canonical testnet public operator must bind to loopback");
      }
      return {
        operatorId: canonicalOperatorId(operator.operatorId),
        chainId: integer(operator.chainId, "canonical testnet public operator chain id", 1),
        issuanceRegistry: address(
          operator.issuanceRegistry,
          "canonical testnet public operator registry",
        ),
        issuerKeyId: bytes32(operator.issuerKeyId, "canonical testnet public operator issuer key"),
        signerAddress: address(operator.signerAddress, "canonical testnet public operator signer"),
        builderSha256: bytes32(
          operator.builderSha256,
          "canonical testnet public operator builder SHA-256",
        ),
        castSha256: bytes32(
          operator.castSha256,
          "canonical testnet public operator cast SHA-256",
        ),
        pollIntervalSeconds: integer(
          operator.pollIntervalSeconds,
          "canonical testnet public operator poll interval",
          5,
          3_600,
        ),
        listenHost: operator.listenHost as "127.0.0.1" | "::1",
        listenPort: integer(
          operator.listenPort,
          "canonical testnet public operator listen port",
          1,
          65_535,
        ),
      };
    })
    .sort((left, right) => left.operatorId.localeCompare(right.operatorId));
  unique(operators.map(({ operatorId }) => operatorId), "canonical testnet public operator ids");
  unique(operators.map(({ signerAddress }) => signerAddress), "canonical testnet public operator signers");

  const fleet = object(candidate.fleet, "canonical testnet public fleet");
  exactKeys(fleet, publicFleetKeys, "canonical testnet public fleet");
  const parsedFleet = parseZkIdentityStatusFleetConfig({
    schema: "org.proofofhumanity.v2-packed-status-fleet-config/1",
    referenceRpcUrl: "https://redacted.invalid",
    chainId: fleet.chainId,
    issuanceRegistry: fleet.issuanceRegistry,
    issuerKeyId: fleet.issuerKeyId,
    threshold: fleet.threshold,
    maxHeartbeatAgeSeconds: fleet.maxHeartbeatAgeSeconds,
    maxBlockLag: fleet.maxBlockLag,
    requestTimeoutMs: 1,
    operators: fleet.operators,
  });
  if (parsedFleet.operators.length !== 2 || parsedFleet.threshold !== 2) {
    throw new Error("canonical testnet public fleet must require both operators");
  }
  return {
    operators,
    fleet: {
      chainId: parsedFleet.chainId,
      issuanceRegistry: parsedFleet.issuanceRegistry,
      issuerKeyId: parsedFleet.issuerKeyId,
      threshold: parsedFleet.threshold,
      maxHeartbeatAgeSeconds: parsedFleet.maxHeartbeatAgeSeconds,
      maxBlockLag: parsedFleet.maxBlockLag,
      operators: [...parsedFleet.operators].sort((left, right) =>
        left.operatorId.localeCompare(right.operatorId),
      ),
    },
  };
}

function assertPublicTopologyMatchesTrustRecord(
  topology: ZkIdentityStatusTestnetPublicTopology,
  trustRecord: ZkIdentityStatusTestnetTrustRecord,
): void {
  if (
    topology.fleet.chainId !== trustRecord.chainId ||
    topology.fleet.issuanceRegistry !== trustRecord.issuanceRegistry ||
    topology.fleet.issuerKeyId !== trustRecord.issuerKeyId
  ) {
    throw new Error("canonical testnet public fleet does not match the trust record");
  }
  for (const [index, expected] of trustRecord.operators.entries()) {
    const operator = topology.operators[index];
    const fleetOperator = topology.fleet.operators[index];
    if (
      operator === undefined ||
      fleetOperator === undefined ||
      operator.operatorId !== expected.operatorId ||
      fleetOperator.operatorId !== expected.operatorId ||
      operator.chainId !== trustRecord.chainId ||
      operator.issuanceRegistry !== trustRecord.issuanceRegistry ||
      operator.issuerKeyId !== trustRecord.issuerKeyId ||
      operator.signerAddress !== expected.signerAddress ||
      fleetOperator.signerAddress !== expected.signerAddress ||
      fleetOperator.baseUrl !== expected.baseUrl ||
      operator.builderSha256 !== trustRecord.builderSha256 ||
      operator.castSha256 !== trustRecord.castSha256
    ) {
      throw new Error("canonical testnet public operator does not match the trust record");
    }
  }
}

export function verifyZkIdentityStatusTestnetPreflightEvidence(
  value: unknown,
): ZkIdentityStatusTestnetPreflightEvidence {
  const candidate = object(value, "canonical testnet preflight evidence");
  exactKeys(candidate, evidenceKeys, "canonical testnet preflight evidence");
  if (candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_EVIDENCE_SCHEMA) {
    throw new Error("unsupported canonical testnet preflight evidence schema");
  }
  const suppliedSha256 = bytes32(
    candidate.evidenceSha256,
    "canonical testnet preflight evidence SHA-256",
    true,
  );
  const rawPayload = {
    schema: candidate.schema,
    trustRecord: candidate.trustRecord,
    topology: candidate.topology,
    providers: candidate.providers,
    report: candidate.report,
  };
  if (sha256(rawPayload) !== suppliedSha256) {
    throw new Error("canonical testnet preflight evidence SHA-256 mismatch");
  }
  const trustRecord = parseZkIdentityStatusTestnetTrustRecord(candidate.trustRecord);
  if (!Array.isArray(candidate.providers)) {
    throw new Error("canonical testnet preflight providers must be an array");
  }
  const providers = candidate.providers.map((value) => {
    const item = object(value, "canonical testnet preflight provider");
    exactKeys(item, providerKeys, "canonical testnet preflight provider");
    return {
      providerId: label(item.providerId, "canonical testnet preflight provider id"),
      observation: item.observation === null ? null : parseObservation(item.observation),
    };
  });
  const report = parseReport(candidate.report);
  const topology = parsePublicTopology(candidate.topology);
  assertPublicTopologyMatchesTrustRecord(topology, trustRecord);
  const reproduced = evaluateZkIdentityStatusTestnetPreflight({
    trustRecord,
    providers,
    observedAt: new Date(report.observedAt),
  });
  if (canonicalJson(reproduced) !== canonicalJson(report)) {
    throw new Error("canonical testnet preflight report cannot be reproduced");
  }
  const normalizedPayload = {
    schema: ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_EVIDENCE_SCHEMA,
    trustRecord,
    topology,
    providers,
    report,
  };
  if (canonicalJson(normalizedPayload) !== canonicalJson(rawPayload)) {
    throw new Error("canonical testnet preflight evidence is not canonically encoded");
  }
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_PREFLIGHT_EVIDENCE_SCHEMA,
    trustRecord,
    topology,
    providers,
    report,
    evidenceSha256: suppliedSha256,
  };
}

export function verifyZkIdentityStatusTestnetPreflightEvidenceAgainstTopology(input: {
  evidence: unknown;
  trustRecord: unknown;
  operatorConfigs: readonly unknown[];
  fleetConfig: unknown;
}): ZkIdentityStatusTestnetPreflightEvidence {
  const evidence = verifyZkIdentityStatusTestnetPreflightEvidence(input.evidence);
  const expected = validateZkIdentityStatusTestnetTopology(input);
  if (
    canonicalJson(evidence.trustRecord) !== canonicalJson(expected.trustRecord) ||
    canonicalJson(evidence.topology) !== canonicalJson(expected.publicTopology)
  ) {
    throw new Error("canonical testnet preflight evidence does not match the reviewed topology");
  }
  return evidence;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } catch (error) {
    const code =
      error !== null && typeof error === "object" && "code" in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code !== "EINVAL" && code !== "ENOTSUP") throw error;
  } finally {
    await handle.close();
  }
}

export async function writeZkIdentityStatusTestnetPreflightEvidence(
  path: string,
  evidence: unknown,
): Promise<void> {
  if (!isAbsolute(path)) throw new Error("canonical testnet preflight evidence path must be absolute");
  const verified = verifyZkIdentityStatusTestnetPreflightEvidence(evidence);
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = join(directory, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    await handle.writeFile(`${JSON.stringify(verified)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    try {
      await link(temporary, path);
    } catch (error) {
      const code =
        error !== null && typeof error === "object" && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (code !== "EEXIST") throw error;
      throw Object.assign(new Error("canonical testnet preflight evidence already exists"), {
        code: "EVIDENCE_ALREADY_EXISTS",
      });
    }
    await unlink(temporary);
    await syncDirectory(directory);
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function readZkIdentityStatusTestnetPreflightEvidence(
  path: string,
): Promise<ZkIdentityStatusTestnetPreflightEvidence> {
  if (!isAbsolute(path)) throw new Error("canonical testnet preflight evidence path must be absolute");
  return verifyZkIdentityStatusTestnetPreflightEvidence(JSON.parse(await readFile(path, "utf8")));
}

export async function captureZkIdentityStatusTestnetPreflight(input: {
  trustRecord: unknown;
  operatorConfigs: readonly unknown[];
  fleetConfig: unknown;
  observedAt?: Date;
}): Promise<ZkIdentityStatusTestnetPreflightEvidence> {
  const topology = validateZkIdentityStatusTestnetTopology(input);
  const readers = [
    ...topology.operatorConfigs.map((config) => ({
      providerId: topology.trustRecord.operators.find(
        ({ operatorId }) => operatorId === config.operatorId,
      )!.rpcProviderId,
      reader: createZkIdentityStatusTestnetViemReader(
        config.rpcUrl,
        topology.fleetConfig.requestTimeoutMs,
      ),
    })),
    {
      providerId: topology.trustRecord.referenceRpcProviderId,
      reader: createZkIdentityStatusTestnetViemReader(
        topology.fleetConfig.referenceRpcUrl,
        topology.fleetConfig.requestTimeoutMs,
      ),
    },
  ];
  const providers = await Promise.all(
    readers.map(async ({ providerId, reader }) => {
      try {
        return {
          providerId,
          observation: await collectZkIdentityStatusTestnetRpcObservation({
            trustRecord: topology.trustRecord,
            reader,
          }),
        };
      } catch {
        return { providerId, observation: null };
      }
    }),
  );
  return createZkIdentityStatusTestnetPreflightEvidence({
    trustRecord: topology.trustRecord,
    publicTopology: topology.publicTopology,
    providers,
    observedAt: input.observedAt,
  });
}
