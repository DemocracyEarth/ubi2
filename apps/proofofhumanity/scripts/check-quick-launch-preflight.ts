/**
 * Transaction-free public preflight for PoH Quick Launch v1.
 *
 * Reads only public configuration and Base Sepolia contract state. It never
 * loads, derives, prints, or requests an issuer/sponsor/deployer secret.
 */

import { createPublicClient, http, type Address, type Hex } from "viem";
import { predicateVerifierAbi } from "../app/abi/predicateVerifier";
import { proofOfHumanityAbi } from "../app/abi/proofOfHumanity";
import {
  QUICK_LAUNCH_CHAIN,
  QUICK_LAUNCH_RELEASE,
  assessQuickLaunchPublicProbe,
} from "../app/quick-launch";

async function main(): Promise<void> {
  const client = createPublicClient({ transport: http(QUICK_LAUNCH_CHAIN.rpcUrl) });
  const [chainId, pohCode, predicateCode, pohOwner, pohIssuer, predicateOwner, predicateIssuer, predicateProver] =
    await Promise.all([
      client.getChainId(),
      client.getCode({ address: QUICK_LAUNCH_CHAIN.pohAddress }),
      client.getCode({ address: QUICK_LAUNCH_CHAIN.predicateAddress }),
      client.readContract({
        address: QUICK_LAUNCH_CHAIN.pohAddress,
        abi: proofOfHumanityAbi,
        functionName: "owner",
      }),
      client.readContract({
        address: QUICK_LAUNCH_CHAIN.pohAddress,
        abi: proofOfHumanityAbi,
        functionName: "issuer",
      }),
      client.readContract({
        address: QUICK_LAUNCH_CHAIN.predicateAddress,
        abi: predicateVerifierAbi,
        functionName: "owner",
      }),
      client.readContract({
        address: QUICK_LAUNCH_CHAIN.predicateAddress,
        abi: predicateVerifierAbi,
        functionName: "issuer",
      }),
      client.readContract({
        address: QUICK_LAUNCH_CHAIN.predicateAddress,
        abi: predicateVerifierAbi,
        functionName: "prover",
      }),
    ]);

  const result = assessQuickLaunchPublicProbe({
    chainId,
    pohAddress: QUICK_LAUNCH_CHAIN.pohAddress,
    predicateAddress: QUICK_LAUNCH_CHAIN.predicateAddress,
    pohCode: (pohCode ?? "0x") as Hex,
    predicateCode: (predicateCode ?? "0x") as Hex,
    pohOwner: pohOwner as Address,
    pohIssuer: pohIssuer as Address,
    predicateOwner: predicateOwner as Address,
    predicateIssuer: predicateIssuer as Address,
    predicateProver: predicateProver as Address,
    selfEndpoint: process.env.NEXT_PUBLIC_SELF_ENDPOINT ?? "",
    selfEnvironment: process.env.NEXT_PUBLIC_SELF_ENV ?? "staging",
  });

  const publicSummary = {
    release: QUICK_LAUNCH_RELEASE.id,
    transactionFree: true,
    chainId,
    chainName: QUICK_LAUNCH_CHAIN.name,
    proofOfHumanity: QUICK_LAUNCH_CHAIN.pohAddress,
    predicateVerifier: QUICK_LAUNCH_CHAIN.predicateAddress,
    owner: pohOwner,
    issuer: pohIssuer,
    predicateOwner,
    predicateIssuer,
    predicateProver,
    selfEnvironment: process.env.NEXT_PUBLIC_SELF_ENV ?? "staging",
    selfEndpointConfigured: Boolean(process.env.NEXT_PUBLIC_SELF_ENDPOINT),
    ready: result.ready,
    errors: result.errors,
  };
  process.stdout.write(`${JSON.stringify(publicSummary, null, 2)}\n`);
  if (!result.ready) process.exitCode = 1;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown public preflight failure.";
  process.stderr.write(`Quick Launch public preflight failed: ${message}\n`);
  process.exitCode = 1;
});
