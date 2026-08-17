#!/usr/bin/env node
/** Read-only live admission preflight. No signer or broadcast path exists here. */
import { readFile } from "node:fs/promises";
import {
  createPublicClient,
  getAddress,
  http,
  parseAbi,
  type Address,
  type Hex,
} from "viem";
import {
  admitZkProductionProfile,
  parseZkProductionProfileManifest,
} from "./zk-production-profile";

const ownerAbi = parseAbi(["function owner() view returns (address)"]);
const predicateVerifierAbi = parseAbi(["function prover() view returns (address)"]);
const registryAbi = parseAbi([
  "function circuits(bytes32 circuitId) view returns (address verifier,bytes32 verifierCodehash,bool active)",
]);

function usage(): never {
  throw new Error(
    "usage: V2_PROFILE_RPC_URL=<rpc> pnpm --filter @ubi2/sdk admit:v2-profile -- <manifest.json>",
  );
}

function boundedFailure(error: unknown, rpcUrl: string | undefined): string {
  const raw = error instanceof Error ? error.message : "unknown failure";
  const firstLine = raw.split(/\r?\n/u).find((line) => line.trim().length > 0) ?? "unknown failure";
  const withoutRpc =
    rpcUrl === undefined || rpcUrl.length === 0
      ? firstLine
      : firstLine.split(rpcUrl).join("<redacted-rpc>");
  return withoutRpc
    .replace(/https?:\/\/\S+/gu, "<redacted-url>")
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .slice(0, 240);
}

const manifestPath = process.argv[2];
const rpcUrl = process.env.V2_PROFILE_RPC_URL;

try {
  if (manifestPath === undefined || process.argv.length !== 3) usage();
  if (rpcUrl === undefined || rpcUrl.length === 0) usage();
  const manifest = parseZkProductionProfileManifest(JSON.parse(await readFile(manifestPath, "utf8")));
  const client = createPublicClient({ transport: http(rpcUrl) });
  const chainId = await client.getChainId();
  const observedAtBlock = await client.getBlockNumber();
  const target = manifest.targets.find((candidate) => candidate.chainId === chainId);
  if (target === undefined) throw new Error("RPC chain is absent from the production profile");

  const [
    governance,
    versionRegistry,
    rawVerifier,
    predicateProver,
    predicateVerifier,
    registryOwner,
    predicateVerifierOwner,
    activeProver,
    circuitRegistration,
  ] = await Promise.all([
    client.getBytecode({ address: target.governance, blockNumber: observedAtBlock }),
    client.getBytecode({ address: target.versionRegistry, blockNumber: observedAtBlock }),
    client.getBytecode({ address: target.rawVerifier, blockNumber: observedAtBlock }),
    client.getBytecode({ address: target.predicateProver, blockNumber: observedAtBlock }),
    client.getBytecode({ address: target.predicateVerifier, blockNumber: observedAtBlock }),
    client.readContract({
      address: target.versionRegistry,
      abi: ownerAbi,
      functionName: "owner",
      blockNumber: observedAtBlock,
    }),
    client.readContract({
      address: target.predicateVerifier,
      abi: ownerAbi,
      functionName: "owner",
      blockNumber: observedAtBlock,
    }),
    client.readContract({
      address: target.predicateVerifier,
      abi: predicateVerifierAbi,
      functionName: "prover",
      blockNumber: observedAtBlock,
    }),
    client.readContract({
      address: target.versionRegistry,
      abi: registryAbi,
      functionName: "circuits",
      args: [manifest.circuit.circuitId],
      blockNumber: observedAtBlock,
    }),
  ]);

  const [registeredVerifier, registeredCodehash, registeredActive] = circuitRegistration;
  const admission = admitZkProductionProfile({
    manifest,
    snapshot: {
      chainId,
      observedAtBlock: observedAtBlock.toString(),
      registryOwner: getAddress(registryOwner) as Address,
      predicateVerifierOwner: getAddress(predicateVerifierOwner) as Address,
      predicateVerifierProver: getAddress(activeProver) as Address,
      circuitRegistration: {
        verifier: getAddress(registeredVerifier) as Address,
        verifierCodehash: registeredCodehash as Hex,
        active: registeredActive,
      },
      runtimeBytecode: {
        governance: governance ?? "0x",
        versionRegistry: versionRegistry ?? "0x",
        rawVerifier: rawVerifier ?? "0x",
        predicateProver: predicateProver ?? "0x",
        predicateVerifier: predicateVerifier ?? "0x",
      },
    },
  });
  process.stdout.write(`${JSON.stringify(admission, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`V2 production profile admission FAILED: ${boundedFailure(error, rpcUrl)}\n`);
  process.exitCode = 1;
}
