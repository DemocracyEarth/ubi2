import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  chmod,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { promisify } from "node:util";
import {
  createZkIdentityPackedStatusAttestation,
  parseZkIdentityPackedStatusSnapshot,
  recoverZkIdentityPackedStatusAttestationSigner,
  zkIdentityPackedStatusAttestationDigest,
} from "@ubi2/sdk";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { CastKeystoreDigestSigner } from "./adapters";

const execute = promisify(execFile);
// Public Hardhat test vector. It is not a credential and must never hold funds.
const testPrivateKey =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8411ddca14bb03ea63";
const testAccount = privateKeyToAccount(testPrivateKey);

async function resolveCast(): Promise<string> {
  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (directory === "") continue;
    const candidate = join(directory, "cast");
    try {
      await access(candidate, constants.X_OK);
      return realpath(candidate);
    } catch {
      // Continue through the finite configured PATH.
    }
  }
  throw new Error("cast is not available for the encrypted-keystore integration test");
}

const directory = await mkdtemp(join(tmpdir(), "ubi2-status-cast-test-"));
try {
  const castPath = await resolveCast();
  const keystoreDirectory = join(directory, "keystores");
  const passwordFile = join(directory, "password");
  const password = "ubi2-public-test-vector-password";
  await writeFile(passwordFile, password, { encoding: "utf8", mode: 0o600 });
  await execute(castPath, [
    "wallet",
    "import",
    "status-test-reconciler",
    "--keystore-dir",
    keystoreDirectory,
    "--private-key",
    testPrivateKey,
    "--unsafe-password",
    password,
  ]);
  const files = await readdir(keystoreDirectory);
  assert.deepEqual(files, ["status-test-reconciler"]);
  const keystorePath = join(keystoreDirectory, files[0]!);
  await chmod(keystorePath, 0o600);
  const castSha256 = `0x${createHash("sha256")
    .update(await readFile(castPath))
    .digest("hex")}` as Hex;
  const signer = await CastKeystoreDigestSigner.create({
    castPath,
    castSha256,
    keystorePath,
    passwordFile,
  });
  const fixture = parseZkIdentityPackedStatusSnapshot(
    JSON.parse(
      await readFile(
        new URL(
          "../../../tools/v2-crypto-bench/fixtures/packed-status-snapshot.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ),
  );
  const signature = await signer.signDigest(zkIdentityPackedStatusAttestationDigest(fixture));
  const recovered = await recoverZkIdentityPackedStatusAttestationSigner(
    createZkIdentityPackedStatusAttestation(fixture, signature),
  );
  assert.equal(recovered, testAccount.address);
  console.log("v2 status operator: encrypted cast keystore EIP-712 digest PASS");
} finally {
  await rm(directory, { recursive: true, force: true });
}
