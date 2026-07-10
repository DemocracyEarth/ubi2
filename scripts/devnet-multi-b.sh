#!/usr/bin/env bash
# Launch a multi-validator ubi2 devnet (M5 Stage B, CFT): 3 VALIDATOR nodes that ROTATE block
# production over a PoH-gated, on-chain validator set `V` (spec 08 §13 setup). Unlike Stage A's single
# designated proposer, every node here holds a validator key AND is seeded into genesis as a Verified
# human + registered juror, so `V = {n1, n2, n3}` on every node by replay, and the round-robin schedule
# `proposer(h, v) = V[(h + v) mod N]` elects a different node each height. Kill any node and a successor
# takes over via the local view-change timer — the chain does not halt (CFT liveness, §5).
#
# Key differences from scripts/devnet-multi.sh (Stage A):
#   * NO UBI2_DESIGNATED_PROPOSER — the schedule reads the on-chain epoch snapshot `V` (§3.3), not a
#     single pinned address.
#   * Every node sets UBI2_PROPOSER_KEY + UBI2_VALIDATOR_KEY (its own validator identity).
#   * Every node sets the SAME UBI2_GENESIS_VALIDATORS (all 3 addresses) so genesis seeds `V` identically.
#
# Usage:
#   ./scripts/devnet-multi-b.sh
#   UBI2_BLOCK_MS=1000 ./scripts/devnet-multi-b.sh
#
# Ports (NON-DEFAULT, distinct from devnet-multi.sh):
#   node i RPC : 127.0.0.1:$((18580 + i))     (18581, 18582, 18583)
#   node i P2P : /ip4/127.0.0.1/tcp/$((19580 + i))
#
# Watch the rotation (any node's RPC):
#   curl -s 127.0.0.1:18581 -d '{"jsonrpc":"2.0","id":1,"method":"ubi_consensusStatus","params":[]}'
#   → { validatorSet:[…3 addrs…], n:3, currentView, scheduledProposer, finalizedHeight, … }
#
# Stop: Ctrl-C (kills every child).
set -euo pipefail
cd "$(dirname "$0")/.."

BLOCK_MS="${UBI2_BLOCK_MS:-2000}"
GENESIS_TIME="${UBI2_GENESIS_TIME:-1700000000}"
RPC_BASE=18580
P2P_BASE=19580

# The 3 validator keys (Anvil accounts #1..#3 — PUBLIC devnet keys, NOT secrets) + their addresses.
KEYS=(
  "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" # 0x7099…
  "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" # 0x3C44…
  "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" # 0x90F7…
)
ADDRS=(
  "70997970C51812dc3A010C7d01b50e0d17dc79C8"
  "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
  "90F79bf6EB2c4f870365E785982E1f101E93b906"
)
# The comma-separated genesis validator set — identical on every node (deterministic `V`).
GENESIS_VALIDATORS="$(IFS=,; echo "${ADDRS[*]}")"

echo "building ubi2-node…"
cargo build -q -p ubi2-node
BIN="target/debug/ubi2-node"

# P2P seeds: node i uses byte i repeated to 32 bytes (matches the m5_stage_b test harness).
seed() { local h; printf -v h '%x' "$1"; printf '%.0s'"$h" {1..64}; }

# Precompute each node's PeerId for a deterministic full cross-bootstrap mesh (no mDNS).
declare -a PIDS
for i in 1 2 3; do
  PIDS[$i]="$("$BIN" peer-id "$(seed "$i")")"
done

DATA_ROOT="$(mktemp -d -t ubi2-multib-XXXXXX)"
declare -a CHILDREN
cleanup() { for pid in "${CHILDREN[@]:-}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

for i in 1 2 3; do
  # Bootstrap to the OTHER two nodes.
  BOOT=""
  for j in 1 2 3; do
    [ "$j" -eq "$i" ] && continue
    ENTRY="/ip4/127.0.0.1/tcp/$((P2P_BASE + j))/p2p/${PIDS[$j]}"
    BOOT="${BOOT:+$BOOT,}$ENTRY"
  done
  DATA_DIR="$DATA_ROOT/node$i"
  mkdir -p "$DATA_DIR"
  echo "starting validator node $i  RPC=127.0.0.1:$((RPC_BASE + i))  addr=0x${ADDRS[$((i-1))]}"
  UBI2_RPC_ADDR="127.0.0.1:$((RPC_BASE + i))" \
  UBI2_P2P_ADDR="/ip4/127.0.0.1/tcp/$((P2P_BASE + i))" \
  UBI2_P2P_SEED="$(seed "$i")" \
  UBI2_BOOTSTRAP="$BOOT" \
  UBI2_PROPOSER_KEY="${KEYS[$((i-1))]}" \
  UBI2_VALIDATOR_KEY="${KEYS[$((i-1))]}" \
  UBI2_GENESIS_VALIDATORS="$GENESIS_VALIDATORS" \
  UBI2_GENESIS_TIME="$GENESIS_TIME" \
  UBI2_BLOCK_MS="$BLOCK_MS" \
  UBI2_DATA_DIR="$DATA_DIR" \
  UBI2_MDNS=0 \
  RUST_LOG="${RUST_LOG:-warn,ubi2_node=info}" \
    "$BIN" &
  CHILDREN+=("$!")
done

echo "3 validators up. Rotation over V=${GENESIS_VALIDATORS}. Ctrl-C to stop."
wait
