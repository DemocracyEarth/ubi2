#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bench_dir="$(cd "$script_dir/.." && pwd)"
repo_dir="$(cd "$bench_dir/../.." && pwd)"
dist_dir="$script_dir/dist"

wasm-pack build "$bench_dir" --target web --out-dir browser/pkg --release -- \
  --features browser --locked

expected_profile_wasm_sha256="f4e5aa36f560ac57c7fe6005af7b064c9ce695705ed9444de924d91f7bab31d5"
actual_profile_wasm_sha256="$(shasum -a 256 "$script_dir/pkg/ubi2_v2_crypto_bench_bg.wasm" | awk '{print $1}')"
if [[ "$actual_profile_wasm_sha256" != "$expected_profile_wasm_sha256" ]]; then
  echo "holder profile WASM digest mismatch: $actual_profile_wasm_sha256" >&2
  exit 1
fi

mkdir -p "$dist_dir"
pnpm --dir "$repo_dir" exec esbuild "$script_dir/holder-reference-worker.ts" \
  --bundle --format=esm --platform=browser --target=es2022 \
  --outfile="$dist_dir/holder-reference-worker.js"
pnpm --dir "$repo_dir" exec esbuild "$script_dir/holder-reference-smoke.ts" \
  --bundle --format=esm --platform=browser --target=es2022 \
  --outfile="$dist_dir/holder-reference-smoke.js"
pnpm --dir "$repo_dir" exec esbuild "$script_dir/holder-profile-worker.ts" \
  --bundle --format=esm --platform=browser --target=es2022 \
  --outfile="$dist_dir/holder-profile-worker.js"
cp "$script_dir/pkg/ubi2_v2_crypto_bench_bg.wasm" "$dist_dir/ubi2_v2_crypto_bench_bg.wasm"

echo "holder reference browser smoke bundle PASS"
