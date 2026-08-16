import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { promisify } from "node:util";
import { isHex, size, type Hex } from "viem";
import type {
  ZkIdentityPackedStatusBuilder,
  ZkIdentityStatusDigestSigner,
} from "./operator";

const execute = promisify(execFile);
const SUBPROCESS_ENV: NodeJS.ProcessEnv = { LANG: "C", LC_ALL: "C" };

async function executable(path: string, expectedSha256: Hex, label: string): Promise<string> {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path`);
  await access(path, constants.X_OK);
  const actual = `0x${createHash("sha256").update(await readFile(path)).digest("hex")}`;
  if (actual !== expectedSha256) throw new Error(`${label} SHA-256 does not match configuration`);
  return path;
}

async function privateRegularFile(
  path: string,
  label: string,
  maximumBytes: number,
): Promise<string> {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path`);
  const metadata = await stat(path);
  if (
    !metadata.isFile() ||
    metadata.size <= 0 ||
    metadata.size > maximumBytes ||
    (metadata.mode & 0o077) !== 0
  ) {
    throw new Error(`${label} must be a regular file inaccessible to group and other users`);
  }
  return path;
}

/** Adapter for the prebuilt deterministic Rust snapshot binary. */
export class RustPackedStatusBuilder implements ZkIdentityPackedStatusBuilder {
  private constructor(
    private readonly binaryPath: string,
    private readonly expectedSha256: Hex,
  ) {}

  static async create(binaryPath: string, expectedSha256: Hex): Promise<RustPackedStatusBuilder> {
    return new RustPackedStatusBuilder(
      await executable(binaryPath, expectedSha256, "status builder binary"),
      expectedSha256,
    );
  }

  async advance(checkpointJson: string, sourceJson: string): Promise<string> {
    await executable(this.binaryPath, this.expectedSha256, "status builder binary");
    const directory = await mkdtemp(join(tmpdir(), "ubi2-status-builder-"));
    const checkpointPath = join(directory, "checkpoint.json");
    const sourcePath = join(directory, "source.json");
    try {
      await writeFile(checkpointPath, checkpointJson, { encoding: "utf8", mode: 0o600 });
      await writeFile(sourcePath, sourceJson, { encoding: "utf8", mode: 0o600 });
      const { stdout } = await execute(
        this.binaryPath,
        ["--advance-status-snapshot", checkpointPath, sourcePath],
        {
          timeout: 120_000,
          maxBuffer: 16 * 1024 * 1024,
          encoding: "utf8",
          env: SUBPROCESS_ENV,
        },
      );
      return stdout.trim();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
}

/**
 * Foundry encrypted-keystore signer. Only file paths reach the child process;
 * raw keys and passwords are never accepted by this adapter.
 */
export class CastKeystoreDigestSigner implements ZkIdentityStatusDigestSigner {
  private constructor(
    private readonly castPath: string,
    private readonly castSha256: Hex,
    private readonly keystorePath: string,
    private readonly passwordFile: string,
  ) {}

  static async create(input: {
    castPath: string;
    castSha256: Hex;
    keystorePath: string;
    passwordFile: string;
  }): Promise<CastKeystoreDigestSigner> {
    return new CastKeystoreDigestSigner(
      await executable(input.castPath, input.castSha256, "cast binary"),
      input.castSha256,
      await privateRegularFile(input.keystorePath, "reconciler keystore", 1024 * 1024),
      await privateRegularFile(input.passwordFile, "reconciler password file", 64 * 1024),
    );
  }

  async signDigest(digest: Hex): Promise<Hex> {
    if (!isHex(digest) || size(digest) !== 32) {
      throw new Error("status operator signing digest must be bytes32");
    }
    await executable(this.castPath, this.castSha256, "cast binary");
    // cast signs this already-derived EIP-712 digest directly. Omitting
    // --no-hash would create an incompatible personal-message signature.
    const { stdout } = await execute(
      this.castPath,
      [
        "wallet",
        "sign",
        digest,
        "--no-hash",
        "--keystore",
        this.keystorePath,
        "--password-file",
        this.passwordFile,
        "--color",
        "never",
      ],
      {
        timeout: 30_000,
        maxBuffer: 16 * 1024,
        encoding: "utf8",
        env: SUBPROCESS_ENV,
      },
    );
    const matches = stdout.match(/0x[0-9a-fA-F]{130}/gu) ?? [];
    if (matches.length !== 1) throw new Error("cast returned an invalid status signature");
    return matches[0]!.toLowerCase() as Hex;
  }
}

/** Used by deployment checks without ever reading secret file contents. */
export async function assertStatusOperatorSecretPaths(input: {
  keystorePath: string;
  passwordFile: string;
}): Promise<void> {
  const keystorePath = await privateRegularFile(
    input.keystorePath,
    "reconciler keystore",
    1024 * 1024,
  );
  const passwordFile = await privateRegularFile(
    input.passwordFile,
    "reconciler password file",
    64 * 1024,
  );
  // Ensure one inode cannot accidentally be passed as both encrypted keystore
  // and password input.
  const [keystore, password] = await Promise.all([stat(keystorePath), stat(passwordFile)]);
  if (keystore.dev === password.dev && keystore.ino === password.ino) {
    throw new Error("reconciler keystore and password file must be separate");
  }
}
