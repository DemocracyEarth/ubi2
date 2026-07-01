#!/usr/bin/env bash
# Launch the ubi2 devnet: a single node serving EVM-compatible JSON-RPC (HTTP+WS).
#
# This now delegates to the `ubi` operator CLI (`ubi node --preset devnet`), which is the discoverable
# entrypoint. The preset == this script's historical behaviour: RPC on 127.0.0.1:8545, 2s blocks,
# wall-clock genesis, no proposer key, sync gateway off. The UBI2_* env vars still work as overrides —
# the CLI flags are sugar over them — so e.g. `UBI2_RPC_ADDR=127.0.0.1:9000 ./scripts/devnet.sh` is honored.
#
# Usage:
#   ./scripts/devnet.sh                          # build + run on 127.0.0.1:8545, 2s blocks
#   ./scripts/devnet.sh --rpc 127.0.0.1:9000     # override the RPC address via a CLI flag
#   UBI2_BLOCK_MS=1000 ./scripts/devnet.sh       # env override still works
#
# Then add to MetaMask: RPC http://127.0.0.1:8545, Chain ID 21826, Symbol UBI.
# Import the PUBLIC dev key printed at startup (or via `ubi keys`) to sign test transfers.
set -euo pipefail
cd "$(dirname "$0")/.."

exec cargo run -q -p ubi2-cli --bin ubi -- node --preset devnet "$@"
