import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  QUICK_LAUNCH_IMAGE_PLATFORM,
  QUICK_LAUNCH_NODE_BUILDER_IMAGE,
  QUICK_LAUNCH_NODE_RUNTIME_IMAGE,
  QUICK_LAUNCH_RUNTIME_ENV_KEYS,
  assessQuickLaunchImageProvenance,
  buildQuickLaunchImagePublisherRoleDocuments,
} from "../app/quick-launch-image-release";
import type { QuickLaunchImageProvenanceInput } from "../app/quick-launch-image-release";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const hash = (character: string) => character.repeat(64);
const valid: QuickLaunchImageProvenanceInput = {
  sourceRevision: "a".repeat(40),
  sourceArchiveSha256: hash("1"),
  dockerfileSha256: hash("2"),
  dockerignoreSha256: hash("3"),
  pnpmfileSha256: hash("8"),
  lockfileSha256: hash("4"),
  builderImage: QUICK_LAUNCH_NODE_BUILDER_IMAGE,
  runtimeImage: QUICK_LAUNCH_NODE_RUNTIME_IMAGE,
  platform: QUICK_LAUNCH_IMAGE_PLATFORM,
  firstImageDigest: digest("5"),
  secondImageDigest: digest("5"),
  sbomSha256: hash("6"),
  scanSummarySha256: hash("7"),
  scannerVersion: "1.24.0",
  criticalFindings: 0,
  highFindings: 0,
  runtimeEnvironmentKeys: [...QUICK_LAUNCH_RUNTIME_ENV_KEYS].reverse(),
  imagePublished: false,
};

const approved = assessQuickLaunchImageProvenance(valid);
assert.equal(approved.readyForPublicationApproval, true);
assert.deepEqual(approved.blockers, []);
assert.equal(approved.transactionFree, true);
assert.match(approved.sourceToImageBindingSha256 ?? "", /^[0-9a-f]{64}$/u);

function rejects(
  patch: Partial<typeof valid>,
  blocker: ReturnType<typeof assessQuickLaunchImageProvenance>["blockers"][number],
) {
  const assessment = assessQuickLaunchImageProvenance({ ...valid, ...patch });
  assert.equal(assessment.readyForPublicationApproval, false);
  assert.ok(assessment.blockers.includes(blocker), `${blocker} not found in ${assessment.blockers}`);
}

rejects({ sourceRevision: "HEAD" }, "source-revision-invalid");
rejects({ pnpmfileSha256: undefined }, "pnpmfile-sha256-invalid");
rejects({ builderImage: "node:22-bookworm-slim" }, "builder-image-not-pinned");
rejects({ runtimeImage: "node:22-bookworm-slim" }, "runtime-image-not-pinned");
rejects({ platform: "linux/arm64" }, "platform-not-linux-amd64");
rejects({ secondImageDigest: digest("8") }, "image-build-not-reproducible");
rejects({ criticalFindings: 1 }, "critical-findings-present");
rejects({ highFindings: 1 }, "high-findings-present");
rejects(
  { runtimeEnvironmentKeys: [...QUICK_LAUNCH_RUNTIME_ENV_KEYS, "ISSUER_PRIVATE_KEY"] },
  "runtime-environment-not-allowlisted",
);
rejects({ imagePublished: true }, "image-publication-observed");
rejects({ imagePublished: undefined }, "image-publication-observed");

const accountId = "123456789012";
const publisher = buildQuickLaunchImagePublisherRoleDocuments(accountId);
assert.equal(publisher.maximumSessionDurationSeconds, 3600);
assert.match(publisher.trustPolicySha256, /^[0-9a-f]{64}$/u);
assert.match(publisher.permissionsPolicySha256, /^[0-9a-f]{64}$/u);
assert.match(publisher.deployerAssumeRoleGrantSha256, /^[0-9a-f]{64}$/u);
assert.deepEqual(publisher.deployerAssumeRoleGrant, {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "AssumeQuickLaunchImagePublisher",
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Resource: "arn:aws:iam::123456789012:role/PoHQuickLaunchImagePublisherRole",
    },
  ],
});
assert.deepEqual(publisher.permissionsPolicy.Statement[0], {
  Sid: "AuthorizeEcrInApprovedRegion",
  Effect: "Allow",
  Action: "ecr:GetAuthorizationToken",
  Resource: "*",
  Condition: { StringEquals: { "aws:RequestedRegion": "us-east-1" } },
});
assert.deepEqual(publisher.permissionsPolicy.Statement[1].Action, [
  "ecr:BatchCheckLayerAvailability",
  "ecr:CompleteLayerUpload",
  "ecr:InitiateLayerUpload",
  "ecr:PutImage",
  "ecr:UploadLayerPart",
]);
assert.deepEqual(publisher.permissionsPolicy.Statement[2].Action, [
  "ecr:BatchGetImage",
  "ecr:DescribeImageScanFindings",
  "ecr:DescribeImages",
  "ecr:DescribeRepositories",
  "ecr:ListImages",
  "ecr:ListTagsForResource",
]);

const policies = JSON.stringify(publisher.permissionsPolicy);
for (const forbidden of [
  "ecr:CreateRepository",
  "ecr:DeleteRepository",
  "ecr:TagResource",
  "ecr:SetRepositoryPolicy",
  "ecr:*",
  "iam:",
  "secretsmanager:",
  "kms:",
]) {
  assert.equal(policies.includes(forbidden), false, `publisher role contains ${forbidden}`);
}
assert.equal(policies.split('"Resource":"*"').length - 1, 1);
assert.equal(JSON.stringify(publisher.deployerAssumeRoleGrant).includes('"Resource":"*"'), false);
assert.throws(() => buildQuickLaunchImagePublisherRoleDocuments("not-an-account"));

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const dockerfile = readFileSync(path.join(root, "apps/proofofhumanity/Dockerfile"), "utf8");
const pnpmfile = readFileSync(path.join(root, ".pnpmfile.cjs"), "utf8");
const pnpmHook = createRequire(import.meta.url)(path.join(root, ".pnpmfile.cjs")).hooks
  .readPackage as (manifest: {
    name?: string;
    version?: string;
    dependencies?: Record<string, string>;
  }) => { dependencies?: Record<string, string> };
const nextConfig = readFileSync(path.join(root, "apps/proofofhumanity/next.config.mjs"), "utf8");
const deterministicBuild = readFileSync(
  path.join(root, "apps/proofofhumanity/scripts/deterministic-next-build.cjs"),
  "utf8",
);
const buildNormalizer = readFileSync(
  path.join(root, "apps/proofofhumanity/scripts/normalize-next-build.mjs"),
  "utf8",
);
const standaloneTsconfig = JSON.parse(
  readFileSync(path.join(root, "apps/proofofhumanity/tsconfig.standalone.json"), "utf8"),
) as { exclude?: string[] };
assert.equal((dockerfile.match(/@sha256:4d676821dff059fd00d277ee4261ef34ea712317fed0737c03941481b5760c96/gu) ?? []).length, 1);
assert.equal((dockerfile.match(/@sha256:9a052c12c6501f1248b682bf6d022276220cb2a65416d215e0973527394d1552/gu) ?? []).length, 1);
assert.ok(dockerfile.includes("gcr.io/distroless/nodejs22-debian13:nonroot"));
assert.ok(dockerfile.includes("COPY .pnpmfile.cjs package.json pnpm-lock.yaml pnpm-workspace.yaml ./"));
assert.ok(dockerfile.includes('CMD ["server.js"]'));
assert.ok(dockerfile.includes("ARG POH_SOURCE_REVISION"));
assert.ok(dockerfile.includes("ARG SOURCE_DATE_EPOCH"));
assert.ok(dockerfile.includes("cp -a apps/proofofhumanity/.next/standalone/. /release/"));
assert.ok(dockerfile.includes('find /release \\\n  -exec touch -h -d "@${SOURCE_DATE_EPOCH}"'));
assert.equal((dockerfile.match(/COPY --from=builder/gu) ?? []).length, 1);
assert.ok(dockerfile.includes("deterministic-next-build.cjs"));
assert.ok(dockerfile.includes("normalize-next-build.mjs"));
assert.ok(dockerfile.includes('org.opencontainers.image.revision="${POH_SOURCE_REVISION}"'));
assert.equal(dockerfile.includes("ISSUER_PRIVATE_KEY"), false);
assert.equal(dockerfile.includes("POH_SPONSOR_PRIVATE_KEY"), false);
assert.ok(pnpmfile.includes('manifest.name === "next"'));
assert.ok(pnpmfile.includes('manifest.version === QUICK_LAUNCH_NEXT_VERSION'));
assert.ok(pnpmfile.includes('const PATCHED_POSTCSS_VERSION = "8.5.28"'));
assert.deepEqual(
  pnpmHook({ name: "next", version: "15.5.25", dependencies: { postcss: "8.4.31" } })
    .dependencies,
  { postcss: "8.5.28" },
);
assert.deepEqual(
  pnpmHook({ name: "next", version: "15.5.24", dependencies: { postcss: "8.4.31" } })
    .dependencies,
  { postcss: "8.4.31" },
);
assert.deepEqual(
  pnpmHook({ name: "unrelated", version: "1.0.0", dependencies: { postcss: "8.4.31" } })
    .dependencies,
  { postcss: "8.4.31" },
);
assert.ok(nextConfig.includes('standaloneApiBuild ? "tsconfig.standalone.json" : "tsconfig.json"'));
assert.ok(nextConfig.includes("generateBuildId: async () => quickLaunchBuildId()"));
assert.ok(nextConfig.includes('/^[0-9a-f]{40}$/'));
assert.deepEqual(standaloneTsconfig.exclude, ["node_modules", "scripts", "test"]);
assert.ok(deterministicBuild.includes("poh-quick-launch-next-build-v1"));
assert.ok(deterministicBuild.includes("NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"));
assert.ok(buildNormalizer.includes("Server Actions are forbidden"));
assert.ok(buildNormalizer.includes("draft mode"));

const buildScript = path.join(root, "ops/proofofhumanity/build-quick-launch-image.sh");
const buildScriptSource = readFileSync(buildScript, "utf8");
assert.ok(buildScriptSource.includes("apps/proofofhumanity/quick-launch-image-evidence"));
assert.equal(buildScriptSource.includes("test-results/quick-launch-image"), false);
const invalidRevision = spawnSync(buildScript, ["HEAD"], { cwd: root, encoding: "utf8" });
assert.equal(invalidRevision.status, 64);
assert.match(invalidRevision.stderr, /exactly 40 lowercase hexadecimal/u);

const occupiedOutput = mkdtempSync(path.join(tmpdir(), "poh-image-evidence-"));
try {
  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).stdout.trim();
  const overwrite = spawnSync(buildScript, [head, occupiedOutput], { cwd: root, encoding: "utf8" });
  assert.equal(overwrite.status, 73);
  assert.match(overwrite.stderr, /non-overwriting/u);
} finally {
  rmSync(occupiedOutput, { recursive: true, force: true });
}

console.log("Quick Launch reproducible image, provenance, scan, and publisher-role failures: PASS");
