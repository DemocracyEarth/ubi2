#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <exact-40-hex-source-revision> [new-output-directory]" >&2
  exit 64
fi

source_revision="$1"
if [[ ! "$source_revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source revision must be exactly 40 lowercase hexadecimal characters" >&2
  exit 64
fi

repo_root="$(git rev-parse --show-toplevel)"
resolved_revision="$(git -C "$repo_root" rev-parse --verify "${source_revision}^{commit}")"
if [[ "$resolved_revision" != "$source_revision" ]]; then
  echo "source revision must resolve without abbreviation or substitution" >&2
  exit 65
fi

output_directory="${2:-$repo_root/apps/proofofhumanity/quick-launch-image-evidence/$source_revision}"
if [[ -e "$output_directory" ]]; then
  echo "output directory already exists; image evidence is non-overwriting: $output_directory" >&2
  exit 73
fi
mkdir -p "$(dirname "$output_directory")"
mkdir "$output_directory"

for command in docker git jq pnpm sha256sum tar; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 69; }
done
docker buildx version >/dev/null
docker scout version >/dev/null

scratch="$(mktemp -d)"
cleanup() {
  rm -rf "$scratch"
}
trap cleanup EXIT
context="$scratch/context"
mkdir "$context"

git -C "$repo_root" archive --format=tar "$source_revision" -- \
  .dockerignore .pnpmfile.cjs package.json pnpm-lock.yaml pnpm-workspace.yaml \
  apps/proofofhumanity packages/sdk > "$scratch/source.tar"
tar -xf "$scratch/source.tar" -C "$context"

source_archive_sha256="$(sha256sum "$scratch/source.tar" | awk '{print $1}')"
dockerfile_sha256="$(sha256sum "$context/apps/proofofhumanity/Dockerfile" | awk '{print $1}')"
dockerignore_sha256="$(sha256sum "$context/.dockerignore" | awk '{print $1}')"
pnpmfile_sha256="$(sha256sum "$context/.pnpmfile.cjs" | awk '{print $1}')"
lockfile_sha256="$(sha256sum "$context/pnpm-lock.yaml" | awk '{print $1}')"
source_date_epoch="$(git -C "$repo_root" show -s --format=%ct "$source_revision")"

image_a="local/proof-of-humanity:${source_revision}-a"
image_b="local/proof-of-humanity:${source_revision}-b"
build_image() {
  local tag="$1"
  local metadata="$2"
  docker buildx build \
    --platform linux/amd64 \
    --file "$context/apps/proofofhumanity/Dockerfile" \
    --build-arg "POH_SOURCE_REVISION=$source_revision" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --provenance=false \
    --sbom=false \
    --no-cache \
    --load \
    --tag "$tag" \
    --metadata-file "$metadata" \
    "$context"
}

build_image "$image_a" "$output_directory/build-a.metadata.json"
build_image "$image_b" "$output_directory/build-b.metadata.json"

image_digest_a="$(jq -er '."containerimage.digest" | select(test("^sha256:[0-9a-f]{64}$"))' "$output_directory/build-a.metadata.json")"
image_digest_b="$(jq -er '."containerimage.digest" | select(test("^sha256:[0-9a-f]{64}$"))' "$output_directory/build-b.metadata.json")"
if [[ "$image_digest_a" != "$image_digest_b" ]]; then
  echo "independent no-cache builds produced different image digests" >&2
  exit 1
fi

runtime_environment_keys="$(docker image inspect "$image_a" --format '{{range .Config.Env}}{{println .}}{{end}}' | awk -F= '{print $1}' | LC_ALL=C sort -u | paste -sd, -)"
if docker history --no-trunc --format '{{.CreatedBy}}' "$image_a" | grep -Eiq 'ISSUER_PRIVATE_KEY|POH_SPONSOR_PRIVATE_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|SECRET_ARN'; then
  echo "image history contains a forbidden credential or secret-reference name" >&2
  exit 1
fi

docker scout sbom --format spdx --output "$output_directory/sbom.spdx.json" "local://$image_a"
docker scout cves --only-severity critical --format sarif \
  --output "$output_directory/vulnerabilities-critical.sarif.json" "local://$image_a"
docker scout cves --only-severity high --format sarif \
  --output "$output_directory/vulnerabilities-high.sarif.json" "local://$image_a"

critical_findings="$(jq '[.runs[]?.results[]?] | length' "$output_directory/vulnerabilities-critical.sarif.json")"
high_findings="$(jq '[.runs[]?.results[]?] | length' "$output_directory/vulnerabilities-high.sarif.json")"
critical_report_sha256="$(sha256sum "$output_directory/vulnerabilities-critical.sarif.json" | awk '{print $1}')"
high_report_sha256="$(sha256sum "$output_directory/vulnerabilities-high.sarif.json" | awk '{print $1}')"
scanner_version="$(docker scout version 2>/dev/null | sed -nE 's/^version: v?([^ ]+).*/\1/p' | head -n 1)"

jq -nS \
  --arg scanner docker-scout \
  --arg scannerVersion "$scanner_version" \
  --arg policy zero-critical-high \
  --argjson criticalFindings "$critical_findings" \
  --argjson highFindings "$high_findings" \
  --arg criticalReportSha256 "$critical_report_sha256" \
  --arg highReportSha256 "$high_report_sha256" \
  '{schema:"org.proofofhumanity.quick-launch.image-scan/1",scanner:$scanner,scannerVersion:$scannerVersion,policy:$policy,criticalFindings:$criticalFindings,highFindings:$highFindings,criticalReportSha256:$criticalReportSha256,highReportSha256:$highReportSha256}' \
  > "$output_directory/scan-summary.json"

sbom_sha256="$(sha256sum "$output_directory/sbom.spdx.json" | awk '{print $1}')"
scan_summary_sha256="$(sha256sum "$output_directory/scan-summary.json" | awk '{print $1}')"

QUICK_LAUNCH_SOURCE_REVISION="$source_revision" \
QUICK_LAUNCH_SOURCE_ARCHIVE_SHA256="$source_archive_sha256" \
QUICK_LAUNCH_DOCKERFILE_SHA256="$dockerfile_sha256" \
QUICK_LAUNCH_DOCKERIGNORE_SHA256="$dockerignore_sha256" \
QUICK_LAUNCH_PNPMFILE_SHA256="$pnpmfile_sha256" \
QUICK_LAUNCH_LOCKFILE_SHA256="$lockfile_sha256" \
QUICK_LAUNCH_BUILDER_IMAGE="docker.io/library/node:22-bookworm-slim@sha256:4d676821dff059fd00d277ee4261ef34ea712317fed0737c03941481b5760c96" \
QUICK_LAUNCH_RUNTIME_IMAGE="gcr.io/distroless/nodejs22-debian13:nonroot@sha256:9a052c12c6501f1248b682bf6d022276220cb2a65416d215e0973527394d1552" \
QUICK_LAUNCH_IMAGE_PLATFORM="linux/amd64" \
QUICK_LAUNCH_FIRST_IMAGE_DIGEST="$image_digest_a" \
QUICK_LAUNCH_SECOND_IMAGE_DIGEST="$image_digest_b" \
QUICK_LAUNCH_SBOM_SHA256="$sbom_sha256" \
QUICK_LAUNCH_SCAN_SUMMARY_SHA256="$scan_summary_sha256" \
QUICK_LAUNCH_SCANNER_VERSION="$scanner_version" \
QUICK_LAUNCH_SCAN_CRITICAL_FINDINGS="$critical_findings" \
QUICK_LAUNCH_SCAN_HIGH_FINDINGS="$high_findings" \
QUICK_LAUNCH_RUNTIME_ENV_KEYS="$runtime_environment_keys" \
QUICK_LAUNCH_IMAGE_PUBLISHED=false \
  pnpm --silent --dir "$repo_root/apps/proofofhumanity" exec tsx scripts/check-quick-launch-image-provenance.ts \
  > "$output_directory/provenance.json"

jq -cS . "$output_directory/provenance.json" | sha256sum | awk '{print $1}' \
  > "$output_directory/provenance.sha256"

echo "Quick Launch image build, SBOM, scan, and provenance: PASS"
echo "source revision: $source_revision"
echo "image digest: $image_digest_a"
echo "provenance SHA-256: $(cat "$output_directory/provenance.sha256")"
echo "output directory: $output_directory"
