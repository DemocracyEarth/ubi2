#!/usr/bin/env bash
# Launch a single-node ubi2 devnet wired for the BROWSER LIGHT NODE (apps/light-node).
#
# The browser light node pins the canonical genesis ANCHOR for its "trust no server" model
# (apps/light-node/src/config.ts), so it only accepts a node started with the EXACT canonical
# genesis: genesis_time = 1700000000, and blocks signed by the pinned PoA proposer (Anvil acct #2).
# Plain ./scripts/devnet.sh uses a wall-clock genesis and no proposer key, so the light node would
# (correctly) reject it as a different network. This script sets those exact values and enables the
# WebSocket sync gateway the browser connects to.
#
# Usage:
#   ./scripts/devnet-lightnode.sh                       # build + run; RPC :8545, sync gateway :8546
#   UBI2_BLOCK_MS=500 ./scripts/devnet-lightnode.sh     # faster blocks
#   rm -rf .devnet-lightnode-data                        # reset the chain to a fresh genesis
#
# Then, in another terminal:
#   pnpm --filter @ubi2/light-node dev                   # http://localhost:3001
#   open 'http://localhost:3001/#address=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
set -euo pipefail
cd "$(dirname "$0")/.."

# ── The canonical devnet genesis the light-node app pins. DO NOT change these or the browser light
#    node will reject this node as a different network (that rejection is the trust model working).
#    Keys are PUBLIC, non-secret standard Anvil accounts; acct #2 is the designated PoA proposer.
GENESIS_TIME=1700000000
PROPOSER_KEY=5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a  # Anvil acct #2 secret
DESIGNATED_PROPOSER=3C44CdDdB6a900fa2b585dd299e03d12FA4293BC                    # its derived address
DEV_ACCOUNT=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266                          # verified human, streams 1 UBI/hr

RPC_ADDR="${UBI2_RPC_ADDR:-127.0.0.1:8545}"
SYNC_ADDR="${UBI2_SYNC_ADDR:-127.0.0.1:8546}"
DATA_DIR="${UBI2_DATA_DIR:-$PWD/.devnet-lightnode-data}"   # isolated from ./scripts/devnet.sh's data
BLOCK_MS="${UBI2_BLOCK_MS:-1000}"

echo "building ubi2-node (release)…"
cargo build --release -p ubi2-node

cat <<EOF

  ubi2 light-node devnet
  ──────────────────────
  JSON-RPC      : http://${RPC_ADDR}
  sync gateway  : ws://${SYNC_ADDR}        ← the browser light node connects here
  chain id      : 21826 (0x5542)
  genesis time  : ${GENESIS_TIME}  (pinned — required by the light node)
  PoA proposer  : 0x${DESIGNATED_PROPOSER}  (Anvil acct #2)
  data dir      : ${DATA_DIR}
                  (rm -rf it to reset; kept separate from the default devnet data)

  Expect this startup log line — it is the anchor the browser pins:
    M5-LN: sealed the seeded genesis anchor … genesis_hash=b24d054f… state_root=aa2c66cd…

  Then, in another terminal:
    pnpm --filter @ubi2/light-node dev
    open 'http://localhost:3001/#address=${DEV_ACCOUNT}'

  Ctrl-C to stop.

EOF

# NOTE: only UBI2_PROPOSER_KEY is set (not UBI2_DESIGNATED_PROPOSER) — for a single, non-P2P node this
# is enough to sign every block as acct #2 (the value the light client's pinned validator set enforces).
exec env \
  UBI2_RPC_ADDR="$RPC_ADDR" \
  UBI2_SYNC_ADDR="$SYNC_ADDR" \
  UBI2_DATA_DIR="$DATA_DIR" \
  UBI2_GENESIS_TIME="$GENESIS_TIME" \
  UBI2_PROPOSER_KEY="$PROPOSER_KEY" \
  UBI2_BLOCK_MS="$BLOCK_MS" \
  ./target/release/ubi2-node
