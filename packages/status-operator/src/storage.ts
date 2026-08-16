import { constants } from "node:fs";
import {
  access,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  parseZkIdentityPackedStatusSnapshot,
  serializeZkIdentityPackedStatusSnapshot,
  zkIdentityPackedStatusSnapshotHash,
} from "@ubi2/sdk";
import {
  parseZkIdentityStatusOperatorArtifact,
  parseZkIdentityStatusOperatorHealth,
  serializeZkIdentityStatusOperatorArtifact,
  serializeZkIdentityStatusOperatorHealth,
  type ZkIdentityStatusOperatorArtifact,
  type ZkIdentityStatusOperatorHealth,
} from "./artifact";

function isMissing(error: unknown): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === "ENOENT"
  );
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

async function atomicWrite(path: string, contents: string): Promise<void> {
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = join(
    directory,
    `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let handle;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await syncDirectory(directory);
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function assertPrivateDirectory(path: string): Promise<void> {
  const metadata = await stat(path);
  if (!metadata.isDirectory() || (metadata.mode & 0o077) !== 0) {
    throw new Error("status operator state directory must use mode 0700 or stricter");
  }
}

/**
 * Atomic, single-writer state for one reconciler. The lock is deliberately
 * fail-closed after an unclean exit: an operator must inspect and remove the
 * stale lock instead of silently starting two writers.
 */
export class ZkIdentityStatusOperatorStore {
  readonly checkpointPath: string;
  readonly latestPath: string;
  readonly healthPath: string;
  readonly artifactsDirectory: string;
  readonly lockPath: string;

  constructor(readonly stateDirectory: string) {
    this.checkpointPath = join(stateDirectory, "checkpoint.json");
    this.latestPath = join(stateDirectory, "public", "latest.json");
    this.healthPath = join(stateDirectory, "public", "health.json");
    this.artifactsDirectory = join(stateDirectory, "public", "artifacts");
    this.lockPath = join(stateDirectory, "operator.lock");
  }

  async initialize(initialCheckpointJson: string): Promise<void> {
    await mkdir(this.artifactsDirectory, { recursive: true, mode: 0o700 });
    await assertPrivateDirectory(this.stateDirectory);
    const canonicalInitial = serializeZkIdentityPackedStatusSnapshot(
      JSON.parse(initialCheckpointJson),
    );
    try {
      parseZkIdentityPackedStatusSnapshot(JSON.parse(await readFile(this.checkpointPath, "utf8")));
    } catch (error) {
      if (!isMissing(error)) throw error;
      await atomicWrite(this.checkpointPath, canonicalInitial);
    }
  }

  async acquireLock(): Promise<() => Promise<void>> {
    await mkdir(this.stateDirectory, { recursive: true, mode: 0o700 });
    await assertPrivateDirectory(this.stateDirectory);
    const handle = await open(
      this.lockPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    await handle.writeFile(
      JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }),
      "utf8",
    );
    await handle.sync();
    let released = false;
    return async () => {
      if (released) return;
      released = true;
      await handle.close();
      await unlink(this.lockPath);
      await syncDirectory(this.stateDirectory);
    };
  }

  async readCheckpointJson(): Promise<string> {
    const checkpoint = await readFile(this.checkpointPath, "utf8");
    return serializeZkIdentityPackedStatusSnapshot(JSON.parse(checkpoint));
  }

  async readLatest(): Promise<ZkIdentityStatusOperatorArtifact | undefined> {
    try {
      return parseZkIdentityStatusOperatorArtifact(
        JSON.parse(await readFile(this.latestPath, "utf8")),
      );
    } catch (error) {
      if (isMissing(error)) return undefined;
      throw error;
    }
  }

  async readHealth(): Promise<ZkIdentityStatusOperatorHealth | undefined> {
    try {
      return parseZkIdentityStatusOperatorHealth(
        JSON.parse(await readFile(this.healthPath, "utf8")),
      );
    } catch (error) {
      if (isMissing(error)) return undefined;
      throw error;
    }
  }

  async readArtifact(snapshotHash: string): Promise<string | undefined> {
    if (!/^0x[0-9a-f]{64}$/u.test(snapshotHash)) return undefined;
    try {
      const artifact = parseZkIdentityStatusOperatorArtifact(
        JSON.parse(
          await readFile(join(this.artifactsDirectory, `${snapshotHash.slice(2)}.json`), "utf8"),
        ),
      );
      if (artifact.attestation.snapshotHash !== snapshotHash) {
        throw new Error("status operator artifact path does not match its content hash");
      }
      return serializeZkIdentityStatusOperatorArtifact(artifact);
    } catch (error) {
      if (isMissing(error)) return undefined;
      throw error;
    }
  }

  async commit(artifactValue: unknown): Promise<ZkIdentityStatusOperatorArtifact> {
    const artifact = parseZkIdentityStatusOperatorArtifact(artifactValue);
    const current = parseZkIdentityPackedStatusSnapshot(
      JSON.parse(await this.readCheckpointJson()),
    );
    const currentBlock = BigInt(current.sourceBlockNumber);
    const incomingBlock = BigInt(artifact.attestation.snapshot.sourceBlockNumber);
    if (
      incomingBlock < currentBlock ||
      (incomingBlock === currentBlock &&
        artifact.attestation.snapshotHash !== zkIdentityPackedStatusSnapshotHash(current))
    ) {
      throw new Error("status operator checkpoint cannot regress or equivocate");
    }
    const serialized = serializeZkIdentityStatusOperatorArtifact(artifact);
    const artifactPath = join(
      this.artifactsDirectory,
      `${artifact.attestation.snapshotHash.slice(2)}.json`,
    );
    let durableArtifact = serialized;
    try {
      const existing = await readFile(artifactPath, "utf8");
      const parsed = parseZkIdentityStatusOperatorArtifact(JSON.parse(existing));
      if (
        parsed.operatorId !== artifact.operatorId ||
        parsed.attestation.snapshotHash !== artifact.attestation.snapshotHash
      ) {
        throw new Error("status operator immutable artifact collision");
      }
      durableArtifact = serializeZkIdentityStatusOperatorArtifact(parsed);
    } catch (error) {
      if (!isMissing(error)) throw error;
      await atomicWrite(artifactPath, serialized);
    }

    // The signed artifact becomes visible before the local replay checkpoint.
    // A crash between these writes safely replays the same finalized range.
    await atomicWrite(this.latestPath, durableArtifact);
    await atomicWrite(
      this.checkpointPath,
      serializeZkIdentityPackedStatusSnapshot(artifact.attestation.snapshot),
    );
    return parseZkIdentityStatusOperatorArtifact(JSON.parse(durableArtifact));
  }

  async writeHealth(health: unknown): Promise<ZkIdentityStatusOperatorHealth> {
    const parsed = parseZkIdentityStatusOperatorHealth(health);
    await atomicWrite(this.healthPath, serializeZkIdentityStatusOperatorHealth(parsed));
    return parsed;
  }

  async assertReadable(): Promise<void> {
    await access(this.checkpointPath, constants.R_OK);
  }
}
