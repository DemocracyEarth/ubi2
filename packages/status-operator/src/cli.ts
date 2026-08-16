#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createZkIdentityFinalizedViemReader } from "@ubi2/sdk";
import {
  assertStatusOperatorSecretPaths,
  CastKeystoreDigestSigner,
  RustPackedStatusBuilder,
} from "./adapters";
import {
  parseZkIdentityStatusFleetConfig,
  parseZkIdentityStatusOperatorConfig,
  readStrictJsonFile,
} from "./config";
import {
  evaluateZkIdentityStatusOperatorFleet,
  fetchZkIdentityStatusOperatorFleet,
} from "./fleet";
import { runZkIdentityStatusOperatorCycle } from "./operator";
import { startZkIdentityStatusOperatorServer } from "./server";
import { ZkIdentityStatusOperatorStore } from "./storage";

function configPath(arguments_: string[]): string {
  if (arguments_.length !== 2 || arguments_[0] !== "--config") {
    throw new Error("status operator requires --config ABSOLUTE_PATH");
  }
  return arguments_[1]!;
}

async function closeServer(server: Awaited<ReturnType<typeof startZkIdentityStatusOperatorServer>>) {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

async function runOperator(path: string): Promise<void> {
  const config = parseZkIdentityStatusOperatorConfig(await readStrictJsonFile(path));
  await assertStatusOperatorSecretPaths(config);
  const store = new ZkIdentityStatusOperatorStore(config.stateDirectory);
  const releaseLock = await store.acquireLock();
  let server: Awaited<ReturnType<typeof startZkIdentityStatusOperatorServer>> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopping = false;
  let resolveStop!: () => void;
  const stopped = new Promise<void>((resolve) => {
    resolveStop = resolve;
  });
  const stop = () => {
    stopping = true;
    if (timer !== undefined) clearTimeout(timer);
    resolveStop();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    await store.initialize(await readFile(config.initialCheckpointPath, "utf8"));
    const [builder, signer] = await Promise.all([
      RustPackedStatusBuilder.create(config.builderPath, config.builderSha256),
      CastKeystoreDigestSigner.create(config),
    ]);
    const reader = createZkIdentityFinalizedViemReader(config.rpcUrl);
    server = await startZkIdentityStatusOperatorServer({
      store,
      host: config.listenHost,
      port: config.listenPort,
    });

    while (!stopping) {
      const result = await runZkIdentityStatusOperatorCycle({
        identity: config,
        reader,
        builder,
        signer,
        store,
      });
      process.stdout.write(
        `${JSON.stringify({
          event: "status_operator_cycle",
          operatorId: config.operatorId,
          ok: result.ok,
          advanced: result.ok ? result.advanced : false,
          errorCode: result.ok ? null : result.errorCode,
        })}\n`,
      );
      if (!stopping) {
        await Promise.race([
          new Promise<void>((resolve) => {
            timer = setTimeout(resolve, config.pollIntervalSeconds * 1_000);
          }),
          stopped,
        ]);
        timer = undefined;
      }
    }
  } finally {
    stopping = true;
    if (timer !== undefined) clearTimeout(timer);
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
    if (server !== undefined) await closeServer(server).catch(() => undefined);
    await releaseLock();
  }
}

async function runFleet(path: string): Promise<void> {
  const config = parseZkIdentityStatusFleetConfig(await readStrictJsonFile(path));
  const referenceReader = createZkIdentityFinalizedViemReader(config.referenceRpcUrl);
  const referenceFinalizedBlock = await Promise.all([
    referenceReader.getChainId(),
    referenceReader.getFinalizedBlock(),
  ])
    .then(([chainId, block]) => (chainId === config.chainId ? block : undefined))
    .catch(() => undefined);
  const report = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: await fetchZkIdentityStatusOperatorFleet(config),
    referenceFinalizedBlock,
  });
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.ready) process.exitCode = 2;
}

async function main(): Promise<void> {
  const [command, ...arguments_] = process.argv.slice(2);
  const path = configPath(arguments_);
  if (command === "run") {
    await runOperator(path);
  } else if (command === "fleet") {
    await runFleet(path);
  } else {
    throw new Error("status operator command must be run or fleet");
  }
}

function fatalCode(error: unknown): string {
  const systemCode =
    error !== null && typeof error === "object" && "code" in error
      ? (error as { code?: unknown }).code
      : undefined;
  if (systemCode === "EEXIST") return "OPERATOR_LOCK_HELD";
  if (systemCode === "EADDRINUSE" || systemCode === "EACCES") return "LISTEN_FAILED";
  const message = error instanceof Error ? error.message : "";
  if (message.includes("SHA-256")) return "EXECUTABLE_INTEGRITY_FAILED";
  if (message.includes("reconciler keystore") || message.includes("reconciler password")) {
    return "SECRET_FILE_INVALID";
  }
  return "CONFIGURATION_OR_STARTUP_FAILED";
}

main().catch((error: unknown) => {
  process.stderr.write(
    `${JSON.stringify({ event: "status_operator_fatal", errorCode: fatalCode(error) })}\n`,
  );
  process.exitCode = 1;
});
