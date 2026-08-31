import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { NextRequest } from "next/server";
import {
  QUICK_LAUNCH_API_RUNTIME,
  assessQuickLaunchApiRuntime,
} from "../app/quick-launch-api-runtime";
import {
  requireBlockchainTransactionsEnabled,
  requireDedicatedQuickLaunchApiOrigin,
} from "../app/lib/server/quick-launch-api-guard";
import { quickLaunchApiHealth } from "../app/lib/server/quick-launch-api-health";
import {
  QUICK_LAUNCH_API_PATHS,
  parseQuickLaunchApiOrigin,
  quickLaunchApiRewrites,
} from "../quick-launch-proxy.mjs";

async function main(): Promise<void> {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, "../../..");
  const templatePath = path.join(repoRoot, "ops/proofofhumanity/aws/quick-launch-api-origin.yaml");
  const dockerfile = readFileSync(path.join(repoRoot, "apps/proofofhumanity/Dockerfile"), "utf8");
  const nextConfig = readFileSync(path.join(repoRoot, "apps/proofofhumanity/next.config.mjs"), "utf8");

  const origin = "https://quick-launch-api.proofofhumanity.org";
  assert.equal(parseQuickLaunchApiOrigin(origin), origin);
  assert.deepEqual(
    quickLaunchApiRewrites(origin),
    QUICK_LAUNCH_API_PATHS.map((source) => ({ source, destination: `${origin}${source}` })),
  );
  assert.deepEqual(QUICK_LAUNCH_API_PATHS, [
    "/api/self-verify",
    "/api/predicate",
    "/api/sponsored-mint",
    "/api/quick-launch-readiness",
  ]);
  for (const rejected of [
    "http://quick-launch-api.proofofhumanity.org",
    "https://user:pass@quick-launch-api.proofofhumanity.org",
    "https://quick-launch-api.proofofhumanity.org/path",
    "https://quick-launch-api.proofofhumanity.org?token=secret",
    "https://localhost",
    "https://proofofhumanity.org",
  ]) {
    assert.throws(() => parseQuickLaunchApiOrigin(rejected));
  }
  assert.ok(dockerfile.includes("ENV POH_BUILD_STANDALONE_API=true"));
  assert.ok(nextConfig.includes('process.env.POH_BUILD_STANDALONE_API === "true"'));

  const disabledEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    POH_API_RUNTIME: QUICK_LAUNCH_API_RUNTIME,
    POH_BLOCKCHAIN_TRANSACTIONS_ENABLED: "false",
    POH_SOURCE_REVISION: "a".repeat(40),
    ISSUER_PRIVATE_KEY: `0x${"1".repeat(64)}`,
    POH_SPONSOR_PRIVATE_KEY: `0x${"2".repeat(64)}`,
  };
  assert.deepEqual(assessQuickLaunchApiRuntime(disabledEnv), {
    dedicatedSingleReplica: true,
    transactionFree: true,
  });
  assert.equal(requireDedicatedQuickLaunchApiOrigin(disabledEnv), null);

  const misplaced = requireDedicatedQuickLaunchApiOrigin({ NODE_ENV: "production" });
  assert.ok(misplaced);
  assert.equal(misplaced.status, 503);
  assert.deepEqual(await misplaced.json(), {
    ok: false,
    code: "dedicated-api-origin-required",
    error: "Quick Launch API requests are accepted only by the dedicated single-replica service.",
  });

  const transactionBlocked = requireBlockchainTransactionsEnabled(disabledEnv);
  assert.ok(transactionBlocked);
  assert.equal(transactionBlocked.status, 503);
  assert.equal((await transactionBlocked.json()).code, "blockchain-transactions-disabled");
  assert.equal(
    requireBlockchainTransactionsEnabled({
      ...disabledEnv,
      POH_BLOCKCHAIN_TRANSACTIONS_ENABLED: "true",
    }),
    null,
  );

  const savedRuntime = process.env.POH_API_RUNTIME;
  const savedTransactionFlag = process.env.POH_BLOCKCHAIN_TRANSACTIONS_ENABLED;
  const savedRpc = process.env.POH_BASE_SEPOLIA_RPC_URL;
  try {
    process.env.POH_API_RUNTIME = QUICK_LAUNCH_API_RUNTIME;
    process.env.POH_BLOCKCHAIN_TRANSACTIONS_ENABLED = "false";
    process.env.POH_BASE_SEPOLIA_RPC_URL = "not-a-url";
    const { POST: sponsoredMintPost } = await import("../app/api/sponsored-mint/route");
    const response = await sponsoredMintPost(
      new NextRequest("https://proofofhumanity.org/api/sponsored-mint?chainId=84532", {
        method: "POST",
        body: "{}",
      }),
    );
    assert.equal(response.status, 503, "transaction kill switch runs before body or RPC validation");
    assert.equal((await response.json()).code, "blockchain-transactions-disabled");
  } finally {
    if (savedRuntime === undefined) delete process.env.POH_API_RUNTIME;
    else process.env.POH_API_RUNTIME = savedRuntime;
    if (savedTransactionFlag === undefined) delete process.env.POH_BLOCKCHAIN_TRANSACTIONS_ENABLED;
    else process.env.POH_BLOCKCHAIN_TRANSACTIONS_ENABLED = savedTransactionFlag;
    if (savedRpc === undefined) delete process.env.POH_BASE_SEPOLIA_RPC_URL;
    else process.env.POH_BASE_SEPOLIA_RPC_URL = savedRpc;
  }

  const health = quickLaunchApiHealth(disabledEnv);
  assert.equal(health.ok, true);
  assert.equal(health.apiRuntime, QUICK_LAUNCH_API_RUNTIME);
  assert.equal(health.transactionFree, true);
  assert.match(health.bootId, /^[0-9a-f-]{36}$/u);
  assert.equal(quickLaunchApiHealth({ ...disabledEnv, POH_SOURCE_REVISION: undefined }).ok, false);
  const healthJson = JSON.stringify(health);
  assert.equal(healthJson.includes(disabledEnv.ISSUER_PRIVATE_KEY!), false);
  assert.equal(healthJson.includes(disabledEnv.POH_SPONSOR_PRIVATE_KEY!), false);

  const template = readFileSync(templatePath, "utf8");
  for (const routePath of ["self-verify", "predicate", "sponsored-mint", "quick-launch-readiness"]) {
    const route = readFileSync(
      path.join(repoRoot, `apps/proofofhumanity/app/api/${routePath}/route.ts`),
      "utf8",
    );
    assert.ok(route.includes("requireDedicatedQuickLaunchApiOrigin()"));
  }
  for (const required of [
    "DesiredCount: 1",
    "MaximumPercent: 100",
    "MinimumHealthyPercent: 0",
    "EnableExecuteCommand: false",
    "POH_BLOCKCHAIN_TRANSACTIONS_ENABLED",
    'Value: "false"',
    "Name: ISSUER_PRIVATE_KEY",
    "Name: POH_SPONSOR_PRIVATE_KEY",
    "ValueFrom: !Ref IssuerPrivateKeySecretArn",
    "ValueFrom: !Ref SponsorPrivateKeySecretArn",
    "TargetType: ip",
    "HealthCheckPath: /api/healthz",
  ]) {
    assert.ok(template.includes(required), `infrastructure template is missing: ${required}`);
  }
  for (const forbidden of [
    "SecretString:",
    "get-secret-value",
    "DesiredCount: 2",
    "MaximumPercent: 200",
  ]) {
    assert.equal(
      template.includes(forbidden),
      false,
      `infrastructure template contains forbidden text: ${forbidden}`,
    );
  }

  console.log(
    "Quick Launch API origin routing, runtime isolation, transaction kill switch, and redaction: PASS",
  );
}

void main();
