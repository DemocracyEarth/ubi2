import {
  collectZkIdentityFinalizedStatusTranscript,
  createZkIdentityPackedStatusAttestation,
  parseZkIdentityPackedStatusSnapshot,
  recoverZkIdentityPackedStatusAttestationSigner,
  serializeZkIdentityStatusSourceTranscript,
  zkIdentityPackedStatusAttestationDigest,
  zkIdentityPackedStatusSnapshotHash,
  type ZkIdentityFinalizedRpcReader,
  type ZkIdentityPackedStatusSnapshot,
} from "@ubi2/sdk";
import { getAddress, type Address, type Hex } from "viem";
import {
  ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA,
  ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA,
  canonicalOperatorId,
  type ZkIdentityStatusOperatorArtifact,
  type ZkIdentityStatusOperatorHealth,
} from "./artifact";
import { ZkIdentityStatusOperatorStore } from "./storage";

export type ZkIdentityStatusOperatorErrorCode =
  | "CHECKPOINT_TRUST_MISMATCH"
  | "INGESTION_FAILED"
  | "BUILDER_FAILED"
  | "BUILDER_OUTPUT_MISMATCH"
  | "SIGNER_FAILED"
  | "SIGNER_MISMATCH"
  | "STORAGE_FAILED"
  | "UNEXPECTED_ERROR";

export class ZkIdentityStatusOperatorError extends Error {
  constructor(readonly code: ZkIdentityStatusOperatorErrorCode) {
    super(code);
    this.name = "ZkIdentityStatusOperatorError";
  }
}

export interface ZkIdentityPackedStatusBuilder {
  advance(checkpointJson: string, sourceJson: string): Promise<string>;
}

/** Signs the exact EIP-712 digest as raw bytes, without an Ethereum message prefix. */
export interface ZkIdentityStatusDigestSigner {
  signDigest(digest: Hex): Promise<Hex>;
}

export interface ZkIdentityStatusOperatorIdentity {
  operatorId: string;
  chainId: number;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  signerAddress: Address;
}

export interface RunZkIdentityStatusOperatorCycleInput {
  identity: ZkIdentityStatusOperatorIdentity;
  reader: ZkIdentityFinalizedRpcReader;
  builder: ZkIdentityPackedStatusBuilder;
  signer: ZkIdentityStatusDigestSigner;
  store: ZkIdentityStatusOperatorStore;
  now?: () => Date;
}

export type ZkIdentityStatusOperatorCycleResult =
  | {
      ok: true;
      advanced: boolean;
      artifact: ZkIdentityStatusOperatorArtifact;
      health: ZkIdentityStatusOperatorHealth;
    }
  | {
      ok: false;
      errorCode: ZkIdentityStatusOperatorErrorCode;
      health?: ZkIdentityStatusOperatorHealth;
    };

function trustedSnapshot(
  value: unknown,
  identity: ZkIdentityStatusOperatorIdentity,
): ZkIdentityPackedStatusSnapshot {
  const snapshot = parseZkIdentityPackedStatusSnapshot(value);
  if (
    snapshot.chainId !== String(identity.chainId) ||
    snapshot.issuanceRegistry.toLowerCase() !== identity.issuanceRegistry.toLowerCase() ||
    snapshot.issuerKeyId !== identity.issuerKeyId.toLowerCase()
  ) {
    throw new ZkIdentityStatusOperatorError("CHECKPOINT_TRUST_MISMATCH");
  }
  return snapshot;
}

function checkpointHealth(
  identity: ZkIdentityStatusOperatorIdentity,
  snapshot: ZkIdentityPackedStatusSnapshot,
  observedAt: string,
  state: "healthy" | "degraded",
  consecutiveFailures: number,
  errorCode: ZkIdentityStatusOperatorErrorCode | null,
): ZkIdentityStatusOperatorHealth {
  return {
    schema: ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA,
    operatorId: identity.operatorId,
    state,
    observedAt,
    consecutiveFailures,
    chainId: snapshot.chainId,
    issuanceRegistry: snapshot.issuanceRegistry,
    issuerKeyId: snapshot.issuerKeyId,
    signerAddress: identity.signerAddress,
    checkpoint: {
      sourceBlockNumber: snapshot.sourceBlockNumber,
      sourceBlockHash: snapshot.sourceBlockHash,
      snapshotHash: zkIdentityPackedStatusSnapshotHash(snapshot),
      root: snapshot.root,
      nextStatusId: snapshot.nextStatusId,
    },
    errorCode,
  };
}

async function signSnapshot(
  snapshot: ZkIdentityPackedStatusSnapshot,
  identity: ZkIdentityStatusOperatorIdentity,
  signer: ZkIdentityStatusDigestSigner,
): Promise<ZkIdentityStatusOperatorArtifact> {
  let signature: Hex;
  try {
    signature = await signer.signDigest(zkIdentityPackedStatusAttestationDigest(snapshot));
  } catch {
    throw new ZkIdentityStatusOperatorError("SIGNER_FAILED");
  }
  const attestation = createZkIdentityPackedStatusAttestation(snapshot, signature);
  let recovered: Address;
  try {
    recovered = await recoverZkIdentityPackedStatusAttestationSigner(attestation);
  } catch {
    throw new ZkIdentityStatusOperatorError("SIGNER_FAILED");
  }
  if (getAddress(recovered) !== getAddress(identity.signerAddress)) {
    throw new ZkIdentityStatusOperatorError("SIGNER_MISMATCH");
  }
  return {
    schema: ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA,
    operatorId: identity.operatorId,
    attestation,
  };
}

function errorCode(error: unknown): ZkIdentityStatusOperatorErrorCode {
  return error instanceof ZkIdentityStatusOperatorError ? error.code : "UNEXPECTED_ERROR";
}

/** Run one non-overlapping, fail-closed finalized checkpoint cycle. */
export async function runZkIdentityStatusOperatorCycle(
  input: RunZkIdentityStatusOperatorCycleInput,
): Promise<ZkIdentityStatusOperatorCycleResult> {
  const identity = {
    ...input.identity,
    operatorId: canonicalOperatorId(input.identity.operatorId),
    signerAddress: getAddress(input.identity.signerAddress),
  };
  const observedAt = (input.now ?? (() => new Date()))().toISOString();
  let checkpoint: ZkIdentityPackedStatusSnapshot | undefined;
  try {
    try {
      checkpoint = trustedSnapshot(
        JSON.parse(await input.store.readCheckpointJson()),
        identity,
      );
    } catch (error) {
      if (error instanceof ZkIdentityStatusOperatorError) throw error;
      throw new ZkIdentityStatusOperatorError("STORAGE_FAILED");
    }

    let transcript;
    try {
      transcript = await collectZkIdentityFinalizedStatusTranscript({
        reader: input.reader,
        chainId: identity.chainId,
        issuanceRegistry: identity.issuanceRegistry,
        issuerKeyId: identity.issuerKeyId,
        anchor: {
          number: BigInt(checkpoint.sourceBlockNumber),
          hash: checkpoint.sourceBlockHash,
          parentHash: checkpoint.sourceBlockParentHash,
        },
        expectedNextStatusId: BigInt(checkpoint.nextStatusId),
      });
    } catch {
      throw new ZkIdentityStatusOperatorError("INGESTION_FAILED");
    }

    const latest = await input.store.readLatest().catch(() => {
      throw new ZkIdentityStatusOperatorError("STORAGE_FAILED");
    });
    const checkpointHash = zkIdentityPackedStatusSnapshotHash(checkpoint);
    if (
      transcript.blocks.length === 0 &&
      latest !== undefined &&
      latest.operatorId === identity.operatorId &&
      latest.attestation.snapshotHash === checkpointHash
    ) {
      let latestSigner: Address;
      try {
        latestSigner = getAddress(
          await recoverZkIdentityPackedStatusAttestationSigner(latest.attestation),
        );
      } catch {
        throw new ZkIdentityStatusOperatorError("SIGNER_FAILED");
      }
      if (latestSigner !== getAddress(identity.signerAddress)) {
        throw new ZkIdentityStatusOperatorError("SIGNER_MISMATCH");
      }
      const health = checkpointHealth(identity, checkpoint, observedAt, "healthy", 0, null);
      await input.store.writeHealth(health).catch(() => {
        throw new ZkIdentityStatusOperatorError("STORAGE_FAILED");
      });
      return { ok: true, advanced: false, artifact: latest, health };
    }

    // Re-entering here means no authenticated latest artifact matched the
    // checkpoint. Even an empty transcript must pass through Rust restore so
    // the initial or recovered Poseidon root is recomputed before signing.
    let output: string;
    try {
      output = await input.builder.advance(
        JSON.stringify(checkpoint),
        serializeZkIdentityStatusSourceTranscript(transcript),
      );
    } catch {
      throw new ZkIdentityStatusOperatorError("BUILDER_FAILED");
    }
    let advanced: ZkIdentityPackedStatusSnapshot;
    try {
      advanced = trustedSnapshot(JSON.parse(output), identity);
    } catch {
      throw new ZkIdentityStatusOperatorError("BUILDER_OUTPUT_MISMATCH");
    }
    const source = transcript.blocks.at(-1) ?? transcript.anchor;
    if (
      advanced.sourceBlockNumber !== source.number ||
      advanced.sourceBlockHash !== source.hash ||
      advanced.sourceBlockParentHash !== source.parentHash
    ) {
      throw new ZkIdentityStatusOperatorError("BUILDER_OUTPUT_MISMATCH");
    }

    const artifact = await signSnapshot(advanced, identity, input.signer);
    const durableArtifact = await input.store.commit(artifact).catch(() => {
      throw new ZkIdentityStatusOperatorError("STORAGE_FAILED");
    });
    checkpoint = advanced;
    let durableSigner: Address;
    try {
      durableSigner = getAddress(
        await recoverZkIdentityPackedStatusAttestationSigner(durableArtifact.attestation),
      );
    } catch {
      throw new ZkIdentityStatusOperatorError("SIGNER_FAILED");
    }
    if (durableSigner !== getAddress(identity.signerAddress)) {
      throw new ZkIdentityStatusOperatorError("SIGNER_MISMATCH");
    }
    const health = checkpointHealth(identity, advanced, observedAt, "healthy", 0, null);
    await input.store.writeHealth(health).catch(() => {
      throw new ZkIdentityStatusOperatorError("STORAGE_FAILED");
    });
    return {
      ok: true,
      advanced: transcript.blocks.length > 0,
      artifact: durableArtifact,
      health,
    };
  } catch (error) {
    const code = errorCode(error);
    if (checkpoint === undefined) return { ok: false, errorCode: code };
    const previousFailures = await input.store
      .readHealth()
      .then((health) => health?.consecutiveFailures ?? 0)
      .catch(() => 0);
    const health = checkpointHealth(
      identity,
      checkpoint,
      observedAt,
      "degraded",
      previousFailures + 1,
      code,
    );
    try {
      await input.store.writeHealth(health);
      return { ok: false, errorCode: code, health };
    } catch {
      return { ok: false, errorCode: "STORAGE_FAILED" };
    }
  }
}
