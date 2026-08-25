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
  readZkIdentityStatusTestnetDrillManifest,
  verifyZkIdentityStatusTestnetDrillEvidence,
} from "./drills";
import {
  assertZkIdentityStatusSupportedTestnetChainId,
  createZkIdentityStatusTestnetEvidence,
  readZkIdentityStatusTestnetEvidenceAgainstFleet,
  writeZkIdentityStatusTestnetEvidence,
} from "./evidence";
import {
  createZkIdentityStatusTestnetExternalAnchorManifest,
  createZkIdentityStatusTestnetProviderIndependenceSubject,
  verifyZkIdentityStatusTestnetExternalAnchorManifestAgainstEvidence,
  writeZkIdentityStatusTestnetExternalAnchorManifest,
  zkIdentityStatusTestnetProviderIndependenceSubjectSha256,
} from "./external-anchor";
import { fetchZkIdentityStatusOperatorFleet } from "./fleet";
import {
  captureZkIdentityStatusTestnetHostAttestation,
  verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig,
  writeZkIdentityStatusTestnetHostAttestationEvidence,
} from "./host-attestation";
import { runZkIdentityStatusOperatorCycle } from "./operator";
import {
  captureZkIdentityStatusTestnetPreflight,
  verifyZkIdentityStatusTestnetPreflightEvidenceAgainstTopology,
  writeZkIdentityStatusTestnetPreflightEvidence,
} from "./readiness";
import { startZkIdentityStatusOperatorServer } from "./server";
import { ZkIdentityStatusOperatorStore } from "./storage";

function options(arguments_: string[], allowed: readonly string[]): Map<string, string> {
  if (arguments_.length % 2 !== 0) {
    throw new Error("status operator options require flag/value pairs");
  }
  const parsed = new Map<string, string>();
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index]!;
    const value = arguments_[index + 1]!;
    if (!allowed.includes(flag) || parsed.has(flag) || value.length === 0) {
      throw new Error("status operator received unsupported or duplicate options");
    }
    parsed.set(flag, value);
  }
  return parsed;
}

function requiredOption(parsed: Map<string, string>, flag: string): string {
  const value = parsed.get(flag);
  if (value === undefined) throw new Error(`status operator requires ${flag} ABSOLUTE_PATH`);
  return value;
}

async function closeServer(server: Awaited<ReturnType<typeof startZkIdentityStatusOperatorServer>>) {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

async function runOperator(path: string): Promise<void> {
  const config = parseZkIdentityStatusOperatorConfig(await readStrictJsonFile(path));
  assertZkIdentityStatusSupportedTestnetChainId(config.chainId);
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

async function runFleet(path: string, evidencePath?: string): Promise<void> {
  const config = parseZkIdentityStatusFleetConfig(await readStrictJsonFile(path));
  assertZkIdentityStatusSupportedTestnetChainId(config.chainId);
  const referenceReader = createZkIdentityFinalizedViemReader(config.referenceRpcUrl);
  const [referenceFinalizedBlock, fetched] = await Promise.all([
    Promise.all([referenceReader.getChainId(), referenceReader.getFinalizedBlock()])
      .then(([chainId, block]) => (chainId === config.chainId ? block : undefined))
      .catch(() => undefined),
    fetchZkIdentityStatusOperatorFleet(config),
  ]);
  const evidence = await createZkIdentityStatusTestnetEvidence({
    config,
    fetched,
    referenceFinalizedBlock,
  });
  if (evidencePath !== undefined) {
    await writeZkIdentityStatusTestnetEvidence(evidencePath, evidence);
  }
  const report = evidence.report;
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.ready) process.exitCode = 2;
}

async function verifyEvidence(path: string, configPath: string): Promise<void> {
  const config = parseZkIdentityStatusFleetConfig(await readStrictJsonFile(configPath));
  const evidence = await readZkIdentityStatusTestnetEvidenceAgainstFleet(path, config);
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_evidence_verified",
      evidenceSha256: evidence.evidenceSha256,
      ready: evidence.report.ready,
      alerts: evidence.report.alerts,
    })}\n`,
  );
  if (!evidence.report.ready) process.exitCode = 2;
}

async function verifyDrillEvidence(manifestPath: string, configPath: string): Promise<void> {
  const [configValue, manifest] = await Promise.all([
    readStrictJsonFile(configPath),
    readZkIdentityStatusTestnetDrillManifest(manifestPath),
  ]);
  const report = await verifyZkIdentityStatusTestnetDrillEvidence({
    config: parseZkIdentityStatusFleetConfig(configValue),
    manifest,
  });
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

async function readinessInputs(parsed: Map<string, string>): Promise<{
  trustRecord: unknown;
  operatorConfigs: readonly [unknown, unknown];
  fleetConfig: unknown;
}> {
  const [trustRecord, operatorA, operatorB, fleetConfig] = await Promise.all([
    readStrictJsonFile(requiredOption(parsed, "--trust-record")),
    readStrictJsonFile(requiredOption(parsed, "--operator-a")),
    readStrictJsonFile(requiredOption(parsed, "--operator-b")),
    readStrictJsonFile(requiredOption(parsed, "--fleet")),
  ]);
  return { trustRecord, operatorConfigs: [operatorA, operatorB], fleetConfig };
}

async function runPreflight(parsed: Map<string, string>): Promise<void> {
  const input = await readinessInputs(parsed);
  const evidence = await captureZkIdentityStatusTestnetPreflight(input);
  await writeZkIdentityStatusTestnetPreflightEvidence(
    requiredOption(parsed, "--evidence"),
    evidence,
  );
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_preflight_captured",
      evidenceSha256: evidence.evidenceSha256,
      ready: evidence.report.ready,
      alerts: evidence.report.alerts,
      externalChecksRequired: evidence.report.externalChecksRequired,
    })}\n`,
  );
  if (!evidence.report.ready) process.exitCode = 2;
}

async function verifyPreflight(parsed: Map<string, string>): Promise<void> {
  const input = await readinessInputs(parsed);
  const evidence = verifyZkIdentityStatusTestnetPreflightEvidenceAgainstTopology({
    ...input,
    evidence: await readStrictJsonFile(requiredOption(parsed, "--input")),
  });
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_preflight_verified",
      evidenceSha256: evidence.evidenceSha256,
      ready: evidence.report.ready,
      alerts: evidence.report.alerts,
      externalChecksRequired: evidence.report.externalChecksRequired,
    })}\n`,
  );
  if (!evidence.report.ready) process.exitCode = 2;
}

async function runHostAttestation(parsed: Map<string, string>): Promise<void> {
  const operatorConfigPath = requiredOption(parsed, "--operator-config");
  const [preflightEvidence, operatorConfig] = await Promise.all([
    readStrictJsonFile(requiredOption(parsed, "--preflight")),
    readStrictJsonFile(operatorConfigPath),
  ]);
  const evidence = await captureZkIdentityStatusTestnetHostAttestation({
    preflightEvidence,
    operatorConfig,
    operatorConfigPath,
    sourceDirectory: requiredOption(parsed, "--source-dir"),
  });
  await writeZkIdentityStatusTestnetHostAttestationEvidence(
    requiredOption(parsed, "--evidence"),
    evidence,
  );
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_host_attestation_captured",
      operatorId: evidence.identity.operatorId,
      evidenceSha256: evidence.evidenceSha256,
      ready: evidence.report.ready,
      alerts: evidence.report.alerts,
      externalChecksRequired: evidence.report.externalChecksRequired,
    })}\n`,
  );
  if (!evidence.report.ready) process.exitCode = 2;
}

async function verifyHostAttestation(parsed: Map<string, string>): Promise<void> {
  const [evidence, preflightEvidence, operatorConfig] = await Promise.all([
    readStrictJsonFile(requiredOption(parsed, "--input")),
    readStrictJsonFile(requiredOption(parsed, "--preflight")),
    readStrictJsonFile(requiredOption(parsed, "--operator-config")),
  ]);
  const verified = verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig({
    evidence,
    preflightEvidence,
    operatorConfig,
  });
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_host_attestation_verified",
      operatorId: verified.identity.operatorId,
      evidenceSha256: verified.evidenceSha256,
      ready: verified.report.ready,
      alerts: verified.report.alerts,
      externalChecksRequired: verified.report.externalChecksRequired,
    })}\n`,
  );
  if (!verified.report.ready) process.exitCode = 2;
}

async function externalAnchorInputs(parsed: Map<string, string>): Promise<{
  preflightEvidence: unknown;
  hostAttestations: readonly [unknown, unknown];
  operatorConfigs: readonly [unknown, unknown];
}> {
  const [preflightEvidence, hostA, hostB, operatorA, operatorB] = await Promise.all([
    readStrictJsonFile(requiredOption(parsed, "--preflight")),
    readStrictJsonFile(requiredOption(parsed, "--host-a")),
    readStrictJsonFile(requiredOption(parsed, "--host-b")),
    readStrictJsonFile(requiredOption(parsed, "--operator-a")),
    readStrictJsonFile(requiredOption(parsed, "--operator-b")),
  ]);
  return {
    preflightEvidence,
    hostAttestations: [hostA, hostB],
    operatorConfigs: [operatorA, operatorB],
  };
}

async function buildExternalAnchorManifest(parsed: Map<string, string>): Promise<void> {
  const [input, references] = await Promise.all([
    externalAnchorInputs(parsed),
    readStrictJsonFile(requiredOption(parsed, "--references")),
  ]);
  const manifest = createZkIdentityStatusTestnetExternalAnchorManifest({
    ...input,
    references,
  });
  await writeZkIdentityStatusTestnetExternalAnchorManifest(
    requiredOption(parsed, "--manifest"),
    manifest,
  );
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_external_anchor_manifest_created",
      manifestSha256: manifest.manifestSha256,
      intrinsicEvidenceValid: manifest.report.intrinsicEvidenceValid,
      liveReadinessClaimed: manifest.report.liveReadinessClaimed,
      externalChecksRequired: manifest.report.externalChecksRequired,
    })}\n`,
  );
}

async function verifyExternalAnchorManifest(parsed: Map<string, string>): Promise<void> {
  const [input, manifest] = await Promise.all([
    externalAnchorInputs(parsed),
    readStrictJsonFile(requiredOption(parsed, "--input")),
  ]);
  const verified = verifyZkIdentityStatusTestnetExternalAnchorManifestAgainstEvidence({
    ...input,
    manifest,
  });
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_external_anchor_manifest_verified",
      manifestSha256: verified.manifestSha256,
      intrinsicEvidenceValid: verified.report.intrinsicEvidenceValid,
      liveReadinessClaimed: verified.report.liveReadinessClaimed,
      externalChecksRequired: verified.report.externalChecksRequired,
    })}\n`,
  );
}

async function printProviderIndependenceSubject(parsed: Map<string, string>): Promise<void> {
  const preflightEvidence = await readStrictJsonFile(requiredOption(parsed, "--preflight"));
  const subject = createZkIdentityStatusTestnetProviderIndependenceSubject(preflightEvidence);
  process.stdout.write(
    `${JSON.stringify({
      event: "status_testnet_provider_independence_subject",
      subject,
      providerIndependenceSubjectSha256:
        zkIdentityStatusTestnetProviderIndependenceSubjectSha256(preflightEvidence),
      liveReadinessClaimed: false,
    })}\n`,
  );
}

async function main(): Promise<void> {
  const [command, ...arguments_] = process.argv.slice(2);
  if (command === "run") {
    const parsed = options(arguments_, ["--config"]);
    await runOperator(requiredOption(parsed, "--config"));
  } else if (command === "fleet") {
    const parsed = options(arguments_, ["--config", "--evidence"]);
    await runFleet(requiredOption(parsed, "--config"), parsed.get("--evidence"));
  } else if (command === "verify-evidence") {
    const parsed = options(arguments_, ["--input", "--config"]);
    await verifyEvidence(
      requiredOption(parsed, "--input"),
      requiredOption(parsed, "--config"),
    );
  } else if (command === "verify-drill-evidence") {
    const parsed = options(arguments_, ["--manifest", "--config"]);
    await verifyDrillEvidence(
      requiredOption(parsed, "--manifest"),
      requiredOption(parsed, "--config"),
    );
  } else if (command === "preflight") {
    const parsed = options(arguments_, [
      "--trust-record",
      "--operator-a",
      "--operator-b",
      "--fleet",
      "--evidence",
    ]);
    await runPreflight(parsed);
  } else if (command === "verify-preflight") {
    const parsed = options(arguments_, [
      "--input",
      "--trust-record",
      "--operator-a",
      "--operator-b",
      "--fleet",
    ]);
    await verifyPreflight(parsed);
  } else if (command === "attest-host") {
    const parsed = options(arguments_, [
      "--preflight",
      "--operator-config",
      "--source-dir",
      "--evidence",
    ]);
    await runHostAttestation(parsed);
  } else if (command === "verify-host-attestation") {
    const parsed = options(arguments_, ["--input", "--preflight", "--operator-config"]);
    await verifyHostAttestation(parsed);
  } else if (command === "build-anchor-manifest") {
    const parsed = options(arguments_, [
      "--preflight",
      "--host-a",
      "--host-b",
      "--operator-a",
      "--operator-b",
      "--references",
      "--manifest",
    ]);
    await buildExternalAnchorManifest(parsed);
  } else if (command === "verify-anchor-manifest") {
    const parsed = options(arguments_, [
      "--input",
      "--preflight",
      "--host-a",
      "--host-b",
      "--operator-a",
      "--operator-b",
    ]);
    await verifyExternalAnchorManifest(parsed);
  } else if (command === "provider-independence-subject") {
    const parsed = options(arguments_, ["--preflight"]);
    await printProviderIndependenceSubject(parsed);
  } else {
    throw new Error(
      "status operator command must be run, fleet, verify-evidence, verify-drill-evidence, preflight, verify-preflight, attest-host, verify-host-attestation, provider-independence-subject, build-anchor-manifest, or verify-anchor-manifest",
    );
  }
}

function fatalCode(error: unknown): string {
  const systemCode =
    error !== null && typeof error === "object" && "code" in error
      ? (error as { code?: unknown }).code
      : undefined;
  if (systemCode === "EVIDENCE_ALREADY_EXISTS") return "EVIDENCE_ALREADY_EXISTS";
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
