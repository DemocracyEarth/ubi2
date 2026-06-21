#!/usr/bin/env bash
# Launch the ubi2 devnet: a single node serving EVM-compatible JSON-RPC (HTTP+WS).
#
# Usage:
#   ./scripts/devnet.sh                # build + run on 127.0.0.1:8545, 2s blocks
#   UBI2_RPC_ADDR=127.0.0.1:9000 ./scripts/devnet.sh
#   UBI2_BLOCK_MS=1000 ./scripts/devnet.sh
#
# Then add to MetaMask: RPC http://127.0.0.1:8545, Chain ID 21826, Symbol UBI.
# Import the PUBLIC dev key printed at startup to sign test transfers.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "building ubi2-node (release)…"
cargo build --release -p ubi2-node

ADDR="${UBI2_RPC_ADDR:-127.0.0.1:8545}"
echo "starting devnet on http://${ADDR} (Ctrl-C to stop)"
exec ./target/release/ubi2-node
