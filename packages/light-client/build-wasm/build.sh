#!/usr/bin/env bash
# Build the ubi2 browser light-node WASM artifact.
#
# EXACT BUILD COMMAND (from the repo root or this directory):
#   bash packages/light-client/build-wasm/build.sh
#
# Output: packages/light-client/wasm/ (the wasm-pack "web" target artefacts)
#   - ubi2_runtime_wasm.js      (glue loader)
#   - ubi2_runtime_wasm_bg.wasm (the compiled WASM blob)
#   - ubi2_runtime_wasm.d.ts    (TypeScript declarations)
#   - package.json
#
# The build uses "wasm-pack build --target web --no-typescript" so the JS glue
# uses an explicit init() pattern (required for Vite static bundling — the loader
# calls init(wasmUrl) before constructing LightState). The TypeScript declarations
# are generated anyway (wasm-pack 0.13+ always emits them).
#
# Prerequisites:
#   cargo / rustup with wasm32-unknown-unknown target added:
#     rustup target add wasm32-unknown-unknown
#   wasm-pack >= 0.13:
#     cargo install wasm-pack

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/runtime-wasm"
OUT_DIR="$REPO_ROOT/packages/light-client/wasm"

echo "[build-wasm] crate: $CRATE_DIR"
echo "[build-wasm] output: $OUT_DIR"

# Ensure the wasm32 target is available.
rustup target add wasm32-unknown-unknown 2>/dev/null || true

# Build.
wasm-pack build \
  --target web \
  --out-dir "$OUT_DIR" \
  --out-name ubi2_runtime_wasm \
  "$CRATE_DIR"

echo "[build-wasm] done — artefacts in $OUT_DIR"
