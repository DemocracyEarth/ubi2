#!/usr/bin/env bash
# Launch a multi-node ubi2 devnet (M5 Stage A): ONE designated proposer + N-1 followers, all on
# localhost with distinct P2P + RPC ports and their own data dirs, wired via a full cross-bootstrap mesh.
#
# This now delegates to the `ubi` operator CLI (`ubi node --preset multi`), which owns the process
# launching: it derives every node's PeerId, wires a deterministic full mesh (no mDNS), starts node 1 as
# the sole proposer (Anvil acct #1) and the rest as followers, and stops them all on Ctrl-C.
#
# Stage A consensus: node 1 is the sole proposer (it holds the proposer key, produces + signs every
# block); the others are followers (they validate + re-execute blocks and gossip txs). A tx sent to any
# node gossips to all; the proposer mines it; every node converges on the same tip + state_root.
#
# Usage:
#   ./scripts/devnet-multi.sh            # 3 nodes (default)
#   N=4 ./scripts/devnet-multi.sh        # 4 nodes (mapped to --nodes)
#   UBI2_BLOCK_MS=1000 ./scripts/devnet-multi.sh
#
# Ports (NON-DEFAULT, to avoid clashing with the single-node devnet on 8545 / a real net):
#   node i RPC : 127.0.0.1:$((18540 + i))     (18541, 18542, 18543, …)
#   node i P2P : /ip4/127.0.0.1/tcp/$((19540 + i))  (19541, 19542, 19543, …)
#
# Watch them (proposer = node 1 on 18541):
#   curl -s 127.0.0.1:18541 -d '{"jsonrpc":"2.0","id":1,"method":"ubi_consensusStatus","params":[]}'
#
# Stop: Ctrl-C (the CLI SIGTERMs every child).
set -euo pipefail
cd "$(dirname "$0")/.."

# The CLI needs the `ubi2-node` binary beside `ubi` (it spawns it per node). Build both up front so the
# first-run compile does not race the launch.
cargo build -q -p ubi2-cli --bin ubi -p ubi2-node

ARGS=(node --preset multi --nodes "${N:-3}")
if [ -n "${UBI2_BLOCK_MS:-}" ]; then
  ARGS+=(--block-ms "$UBI2_BLOCK_MS")
fi
if [ -n "${UBI2_GENESIS_TIME:-}" ]; then
  ARGS+=(--genesis-time "$UBI2_GENESIS_TIME")
fi

exec cargo run -q -p ubi2-cli --bin ubi -- "${ARGS[@]}"
