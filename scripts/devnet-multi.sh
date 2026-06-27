#!/usr/bin/env bash
# Launch a multi-node ubi2 devnet (M5 Stage A): ONE designated proposer + N-1 followers, all on
# localhost with distinct P2P + RPC ports and their own data dirs, wired via a shared bootstrap peer.
#
# Stage A consensus: node 1 is the sole proposer (it holds the proposer key, produces + signs every
# block); the others are followers (they validate + re-execute blocks and gossip txs). A tx sent to any
# node gossips to all; the proposer mines it; every node converges on the same tip + state_root.
#
# Usage:
#   ./scripts/devnet-multi.sh            # 3 nodes (default)
#   N=4 ./scripts/devnet-multi.sh        # 4 nodes
#   UBI2_BLOCK_MS=1000 ./scripts/devnet-multi.sh
#
# Ports (NON-DEFAULT, to avoid clashing with the single-node devnet on 8545 / a real net):
#   node i RPC : 127.0.0.1:$((RPC_BASE + i))     (RPC_BASE=18540 ⇒ 18541, 18542, 18543, …)
#   node i P2P : /ip4/127.0.0.1/tcp/$((P2P_BASE + i))  (P2P_BASE=19540 ⇒ 19541, 19542, 19543, …)
#
# Watch them:
#   curl -s 127.0.0.1:18541 -d '{"jsonrpc":"2.0","id":1,"method":"ubi_getPeers","params":[]}'
#   curl -s 127.0.0.1:18542 -d '{"jsonrpc":"2.0","id":1,"method":"ubi_consensusStatus","params":[]}'
#   curl -s 127.0.0.1:18543 -d '{"jsonrpc":"2.0","id":1,"method":"ubi_stateRoot","params":[]}'
#
# Stop: Ctrl-C (this script SIGTERMs every child + cleans up).
set -euo pipefail
cd "$(dirname "$0")/.."

N="${N:-3}"
RPC_BASE="${RPC_BASE:-18540}"
P2P_BASE="${P2P_BASE:-19540}"
BLOCK_MS="${UBI2_BLOCK_MS:-2000}"
# A FIXED genesis time pins every node's genesis hash to the same value (the network-identity anchor).
GENESIS_TIME="${UBI2_GENESIS_TIME:-1700000000}"

# PUBLIC, NON-SECRET devnet keys (standard Hardhat/Anvil accounts). The proposer signs blocks with
# acct #1's key; its derived address is the designated proposer every follower validates against.
#   acct #1 key  : 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
#   acct #1 addr : 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
PROPOSER_KEY="59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
DESIGNATED_PROPOSER="70997970C51812dc3A010C7d01b50e0d17dc79C8"

# Per-node data dirs + per-run logs under a gitignored root (a crash leaves logs to inspect; a restart
# resumes deterministically — FU-3).
DATA_ROOT=".ubi2-multi"
RUN_DIR="$DATA_ROOT/logs-$$"
mkdir -p "$RUN_DIR"
PIDS=()

cleanup() {
  echo
  echo "stopping ${#PIDS[@]} node(s)…"
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "devnet stopped. logs kept at $RUN_DIR (data dirs under $DATA_ROOT)."
}
trap cleanup EXIT INT TERM

echo "building ubi2-node (release)…"
cargo build --release -p ubi2-node
BIN="./target/release/ubi2-node"

# Each node gets a FIXED Ed25519 transport seed → a stable, precomputable PeerId. We derive every
# node's PeerId up front (the `ubi2-node peer-id <seed>` utility) so we can wire a FULL cross-bootstrap
# mesh deterministically — every node dials every other — WITHOUT relying on mDNS (unavailable in many
# sandboxed/CI networks). Node i's seed is the hex of `i` repeated to 64 chars. NON-SECRET devnet values.
declare -a SEED PID PEERID P2PADDR RPCADDR
for i in $(seq 1 "$N"); do
  d=$(printf '%x' "$i")
  SEED[$i]=$(printf "%0.s$d" $(seq 1 64))
  PEERID[$i]=$("$BIN" peer-id "${SEED[$i]}")
  P2PADDR[$i]="/ip4/127.0.0.1/tcp/$((P2P_BASE + i))"
  RPCADDR[$i]="127.0.0.1:$((RPC_BASE + i))"
done

# Build node i's bootstrap list = the full multiaddrs of every OTHER node (a complete mesh).
bootstrap_for() {
  local self="$1" out=""
  for j in $(seq 1 "$N"); do
    [ "$j" -eq "$self" ] && continue
    out+="${P2PADDR[$j]}/p2p/${PEERID[$j]},"
  done
  echo "${out%,}"
}

echo "starting $N nodes (proposer = node 1) …"
for i in $(seq 1 "$N"); do
  BOOT=$(bootstrap_for "$i")
  if [ "$i" -eq 1 ]; then
    ROLE="PROPOSER"
    PROP_ENV="UBI2_PROPOSER_KEY=$PROPOSER_KEY"
  else
    ROLE="follower"
    PROP_ENV=""
  fi
  env \
    UBI2_RPC_ADDR="${RPCADDR[$i]}" \
    UBI2_P2P_ADDR="${P2PADDR[$i]}" \
    UBI2_P2P_SEED="${SEED[$i]}" \
    UBI2_BOOTSTRAP="$BOOT" \
    UBI2_DESIGNATED_PROPOSER="$DESIGNATED_PROPOSER" \
    UBI2_GENESIS_TIME="$GENESIS_TIME" \
    UBI2_BLOCK_MS="$BLOCK_MS" \
    UBI2_DATA_DIR="$DATA_ROOT/node$i" \
    RUST_LOG="${RUST_LOG:-info}" \
    $PROP_ENV \
    "$BIN" >"$RUN_DIR/node$i.log" 2>&1 &
  PID[$i]=$!
  PIDS+=($!)
  echo "  node $i  RPC http://${RPCADDR[$i]}  P2P ${P2PADDR[$i]}  PeerId ${PEERID[$i]}  ($ROLE)"
done

echo
echo "all $N nodes up. logs: $RUN_DIR/node*.log"
echo
echo "watch the network form (peers, heights, state roots):"
echo "  for p in $(seq 1 "$N" | sed "s/^/$RPC_BASE+/" | bc | tr '\n' ' '); do \\"
echo "    echo -n \"node :\$p  peers=\"; \\"
echo "    curl -s 127.0.0.1:\$p -H 'content-type: application/json' \\"
echo "      -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ubi_getPeers\",\"params\":[]}' | grep -oc peerId; \\"
echo "  done"
echo
echo "consensus status of node 1:"
echo "  curl -s 127.0.0.1:$((RPC_BASE + 1)) -H 'content-type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ubi_consensusStatus\",\"params\":[]}'"
echo
echo "send a tx to node 2 and watch it appear on node 1 & 3 (it is gossiped, not resubmitted)."
echo
echo "Ctrl-C to stop all nodes."

# Hold until interrupted (Ctrl-C → the EXIT trap stops every node). Poll node liveness so a crash is
# surfaced promptly rather than silently leaving a degraded network.
while true; do
  for i in $(seq 1 "$N"); do
    if ! kill -0 "${PID[$i]}" 2>/dev/null; then
      echo "node $i (pid ${PID[$i]}) exited — see $RUN_DIR/node$i.log; shutting the rest down."
      exit 1
    fi
  done
  sleep 2
done
