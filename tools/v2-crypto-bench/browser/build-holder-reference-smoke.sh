#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bench_dir="$(cd "$script_dir/.." && pwd)"
repo_dir="$(cd "$bench_dir/../.." && pwd)"
dist_dir="$script_dir/dist"

wasm-pack build "$bench_dir" --target web --out-dir browser/pkg --release -- \
  --features browser --locked

mkdir -p "$dist_dir"
pnpm --dir "$repo_dir" exec esbuild "$script_dir/holder-reference-worker.ts" \
  --bundle --format=esm --platform=browser --target=es2022 \
  --outfile="$dist_dir/holder-reference-worker.js"
pnpm --dir "$repo_dir" exec esbuild "$script_dir/holder-reference-smoke.ts" \
  --bundle --format=esm --platform=browser --target=es2022 \
  --outfile="$dist_dir/holder-reference-smoke.js"
cp "$script_dir/pkg/ubi2_v2_crypto_bench_bg.wasm" "$dist_dir/ubi2_v2_crypto_bench_bg.wasm"

echo "holder reference browser smoke bundle PASS"
