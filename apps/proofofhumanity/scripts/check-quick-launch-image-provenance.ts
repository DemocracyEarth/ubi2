import { assessQuickLaunchImageProvenance } from "../app/quick-launch-image-release";

function count(name: string): number | undefined {
  const raw = process.env[name]?.trim();
  if (!raw || !/^[0-9]+$/u.test(raw)) return undefined;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : undefined;
}

function booleanValue(name: string): boolean | undefined {
  const raw = process.env[name]?.trim();
  if (raw === "true") return true;
  if (raw === "false") return false;
  return undefined;
}

const evidence = assessQuickLaunchImageProvenance({
  sourceRevision: process.env.QUICK_LAUNCH_SOURCE_REVISION,
  sourceArchiveSha256: process.env.QUICK_LAUNCH_SOURCE_ARCHIVE_SHA256,
  dockerfileSha256: process.env.QUICK_LAUNCH_DOCKERFILE_SHA256,
  dockerignoreSha256: process.env.QUICK_LAUNCH_DOCKERIGNORE_SHA256,
  pnpmfileSha256: process.env.QUICK_LAUNCH_PNPMFILE_SHA256,
  lockfileSha256: process.env.QUICK_LAUNCH_LOCKFILE_SHA256,
  builderImage: process.env.QUICK_LAUNCH_BUILDER_IMAGE,
  runtimeImage: process.env.QUICK_LAUNCH_RUNTIME_IMAGE,
  platform: process.env.QUICK_LAUNCH_IMAGE_PLATFORM,
  firstImageDigest: process.env.QUICK_LAUNCH_FIRST_IMAGE_DIGEST,
  secondImageDigest: process.env.QUICK_LAUNCH_SECOND_IMAGE_DIGEST,
  sbomSha256: process.env.QUICK_LAUNCH_SBOM_SHA256,
  scanSummarySha256: process.env.QUICK_LAUNCH_SCAN_SUMMARY_SHA256,
  scannerVersion: process.env.QUICK_LAUNCH_SCANNER_VERSION,
  criticalFindings: count("QUICK_LAUNCH_SCAN_CRITICAL_FINDINGS"),
  highFindings: count("QUICK_LAUNCH_SCAN_HIGH_FINDINGS"),
  runtimeEnvironmentKeys: process.env.QUICK_LAUNCH_RUNTIME_ENV_KEYS?.split(",").filter(Boolean),
  imagePublished: booleanValue("QUICK_LAUNCH_IMAGE_PUBLISHED"),
});

// This transaction-free output contains only public source/image hashes, package-scan counts,
// allowlisted environment-key names and blockers. Never add environment values or registry credentials.
console.log(JSON.stringify(evidence, null, 2));
if (!evidence.readyForPublicationApproval) process.exitCode = 1;
