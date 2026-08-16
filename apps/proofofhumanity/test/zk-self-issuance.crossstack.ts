/**
 * SDK ↔ production-contract integration for the transitional Self issuance bridge.
 * A raw nullifier is constructed (no passport/phone), scoped off-chain, signed
 * through the SDK, and consumed by the real bridge + registry on Anvil.
 */
import { execSync, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  getAddress,
  http,
  keccak256,
  stringToBytes,
  type Abi,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  encodeZkSelfIssuance,
  zkIssuanceDomainHash,
  zkSelfIssuanceAuthorizationDigest,
  zkSelfIssuanceDuplicateKey,
  zkSelfIssuanceTypedData,
  zkSelfVerifierConfigId,
  type ZkSelfIssuanceAuthorization,
} from "@ubi2/sdk";

const dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(dirname, "../../../contracts");
const registryArtifactPath = path.join(
  contractsDir,
  "out/ZkIdentityIssuanceRegistry.sol/ZkIdentityIssuanceRegistry.json",
);
const bridgeArtifactPath = path.join(
  contractsDir,
  "out/ZkIdentitySelfIssuanceBridge.sol/ZkIdentitySelfIssuanceBridge.json",
);

const rpcUrl = "http://127.0.0.1:18546";
const chainId = 31_337;
const ownerKey =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const authorityKey =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const subjectKey =
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;

const chain = defineChain({
  id: chainId,
  name: "Anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [rpcUrl] } },
});

type Artifact = { abi: Abi; bytecode: { object: Hex } };
let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string): void {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.error(`  ✗ ${message}`);
  }
}

function assertEqual<T>(actual: T, expected: T, message: string): void {
  assert(actual === expected, `${message} (got ${String(actual)}, want ${String(expected)})`);
}

async function waitForAnvil(): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const response = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      });
      if (response.ok) return;
    } catch {
      // Anvil is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Anvil did not become ready");
}

async function main(): Promise<void> {
  console.log("\n=== v2 Self issuance SDK ↔ contract integration ===\n");
  execSync("forge build", { cwd: contractsDir, stdio: "inherit" });
  const registryArtifact = JSON.parse(readFileSync(registryArtifactPath, "utf8")) as Artifact;
  const bridgeArtifact = JSON.parse(readFileSync(bridgeArtifactPath, "utf8")) as Artifact;
  assert(registryArtifact.bytecode.object.length > 2, "loaded production issuance registry bytecode");
  assert(bridgeArtifact.bytecode.object.length > 2, "loaded production Self bridge bytecode");

  const owner = privateKeyToAccount(ownerKey);
  const authority = privateKeyToAccount(authorityKey);
  const subject = privateKeyToAccount(subjectKey);
  const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
  const ownerWallet = createWalletClient({ account: owner, chain, transport: http(rpcUrl) });
  const subjectWallet = createWalletClient({ account: subject, chain, transport: http(rpcUrl) });
  const anvil: ChildProcess = spawn("anvil", ["--port", "18546", "--silent"], { stdio: "ignore" });

  try {
    await waitForAnvil();
    const registryDeploy = await ownerWallet.deployContract({
      abi: registryArtifact.abi,
      bytecode: registryArtifact.bytecode.object,
      args: [owner.address],
    });
    const registry = (await publicClient.waitForTransactionReceipt({ hash: registryDeploy }))
      .contractAddress as Address;
    const issuerKeyId = keccak256(stringToBytes("issuer-key:self:crossstack:v1"));
    const register = await publicClient.simulateContract({
      account: owner,
      address: registry,
      abi: registryArtifact.abi,
      functionName: "registerIssuerKey",
      args: [issuerKeyId],
    });
    await publicClient.waitForTransactionReceipt({ hash: await ownerWallet.writeContract(register.request) });

    const selfConfigId = zkSelfVerifierConfigId({
      scope: "proofofhumanity",
      endpoint: "https://test.example/api/self-verify",
      environment: "staging",
      attestationId: 1,
      verifierPackage: "@selfxyz/core@1.0.8",
    });
    const bridgeDeploy = await ownerWallet.deployContract({
      abi: bridgeArtifact.abi,
      bytecode: bridgeArtifact.bytecode.object,
      args: [registry, issuerKeyId, authority.address, selfConfigId],
    });
    const bridge = (await publicClient.waitForTransactionReceipt({ hash: bridgeDeploy }))
      .contractAddress as Address;
    const authorize = await publicClient.simulateContract({
      account: owner,
      address: registry,
      abi: registryArtifact.abi,
      functionName: "authorizeIssuanceAuthority",
      args: [issuerKeyId, bridge],
    });
    await publicClient.waitForTransactionReceipt({ hash: await ownerWallet.writeContract(authorize.request) });

    const onChainDomain = (await publicClient.readContract({
      address: registry,
      abi: registryArtifact.abi,
      functionName: "issuanceDomain",
    })) as Hex;
    assertEqual(
      onChainDomain,
      zkIssuanceDomainHash({ chainId, registry }),
      "registry issuance domain matches the SDK",
    );

    const rawSelfNullifier = 123_456_789n;
    const duplicateKey = zkSelfIssuanceDuplicateKey({
      issuanceDomain: onChainDomain,
      selfNullifier: rawSelfNullifier,
    });
    const currentEpoch = Number(
      await publicClient.readContract({
        address: registry,
        abi: registryArtifact.abi,
        functionName: "currentEpoch",
      }),
    );
    const latestBlock = await publicClient.getBlock();
    const authorization: ZkSelfIssuanceAuthorization = {
      subject: getAddress(subject.address),
      duplicateKey,
      credentialCommitment: 987_654_321n,
      issuerKeyId,
      expectedStatusId: 1,
      expectedEpoch: currentEpoch,
      deadline: latestBlock.timestamp + 600n,
      selfConfigId,
    };
    const signature = await authority.signTypedData(
      zkSelfIssuanceTypedData({ chainId, bridge, authorization }),
    );
    const localDigest = zkSelfIssuanceAuthorizationDigest({ chainId, bridge, authorization });
    const onChainDigest = (await publicClient.readContract({
      address: bridge,
      abi: bridgeArtifact.abi,
      functionName: "hashAuthorization",
      args: [authorization],
    })) as Hex;
    assertEqual(localDigest, onChainDigest, "SDK EIP-712 digest matches the production bridge");

    const data = encodeZkSelfIssuance({ authorization, signature });
    const issueHash = await subjectWallet.sendTransaction({ to: bridge, data });
    const issueReceipt = await publicClient.waitForTransactionReceipt({ hash: issueHash });
    assertEqual(issueReceipt.status, "success", "proof-bound subject submits SDK calldata successfully");
    assertEqual(
      await publicClient.readContract({
        address: registry,
        abi: registryArtifact.abi,
        functionName: "credentialCommitmentAt",
        args: [issuerKeyId, 1],
      }),
      authorization.credentialCommitment,
      "registry records the exact proof-bound commitment",
    );

    const rawWord = rawSelfNullifier.toString(16).padStart(64, "0");
    assert(!data.slice(10).includes(rawWord), "bridge calldata omits the raw Self nullifier");
    for (const log of issueReceipt.logs) {
      const encodedLog = `${log.topics.join("")}${log.data}`.toLowerCase();
      assert(!encodedLog.includes(rawWord), "issuance log omits the raw Self nullifier");
      assert(!encodedLog.includes(duplicateKey.slice(2)), "issuance log omits the scoped duplicate key");
    }

    const duplicateAuthorization: ZkSelfIssuanceAuthorization = {
      ...authorization,
      credentialCommitment: 111_222_333n,
      expectedStatusId: 2,
    };
    const duplicateSignature = await authority.signTypedData(
      zkSelfIssuanceTypedData({ chainId, bridge, authorization: duplicateAuthorization }),
    );
    let duplicateRejected = false;
    try {
      await publicClient.call({
        account: subject.address,
        to: bridge,
        data: encodeZkSelfIssuance({
          authorization: duplicateAuthorization,
          signature: duplicateSignature,
        }),
      });
    } catch (error) {
      duplicateRejected = String(error).includes("reverted");
    }
    assert(duplicateRejected, "a second authorization for the same passport-scoped key reverts");
  } finally {
    anvil.kill("SIGKILL");
  }

  console.log(`\n=== ${passed} passed, ${failed} failed ===\n`);
  if (failed > 0) process.exit(1);
}

main().catch((error) => {
  console.error("\nFATAL:", error);
  process.exit(1);
});
