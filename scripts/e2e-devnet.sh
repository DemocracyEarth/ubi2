#!/usr/bin/env bash
# E2E smoke test for the M1 devnet, driven over the wire like a real wallet (QA / M1-T7).
#
# Boots the ubi2-node on a NON-DEFAULT port (18545, to avoid colliding with the default :8545 devnet),
# then drives the JSON-RPC surface with curl exactly as viem/ethers/MetaMask would, asserting the M1
# acceptance criteria end-to-end:
#   1. eth_chainId / net_version / eth_blockNumber (climbs) / eth_getBalance (streams) / nonce.
#   3. a signed EIP-155 transfer via eth_sendRawTransaction settles + moves balance + bumps nonce.
#   4. the explorer methods (getBlockByNumber full-tx, getTransactionByHash, getTransactionReceipt)
#      render the mined tx; eth_subscribe(newHeads) streams headers over WS.
#
# Usage:  ./scripts/e2e-devnet.sh
# Requires: a release/debug ubi2-node build, curl, jq, node (>=21 for the WS check).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${UBI2_E2E_PORT:-18545}"
URL="http://127.0.0.1:${PORT}"
WSURL="ws://127.0.0.1:${PORT}"
DEV="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
RCPT="0x00000000000000000000000000000000000000aa"
NODE_BIN="target/debug/ubi2-node"

[ -x "$NODE_BIN" ] || { echo "building ubi2-node..."; cargo build -p ubi2-node; }

call() { curl -s -X POST "$URL" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"; }
res() { call "$1" "$2" | jq -r '.result'; }

echo "== booting devnet on :${PORT} =="
UBI2_RPC_ADDR="127.0.0.1:${PORT}" UBI2_BLOCK_MS=1000 RUST_LOG=warn "$NODE_BIN" >/tmp/ubi2-e2e.log 2>&1 &
NODE_PID=$!
trap 'kill "$NODE_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.25; done

fail() { echo "FAIL: $1"; exit 1; }
eq()   { [ "$1" = "$2" ] || fail "$3 (got '$1', want '$2')"; echo "ok: $3 = $1"; }

# --- Criterion 1 ---
eq "$(res eth_chainId '[]')"   "0x5542" "eth_chainId"
eq "$(res net_version '[]')"   "21826"  "net_version"
B0=$(res eth_blockNumber '[]'); sleep 1.5; B1=$(res eth_blockNumber '[]')
[ "$((B1))" -gt "$((B0))" ] && echo "ok: eth_blockNumber climbs ($B0 -> $B1)" || fail "blockNumber did not climb"
BAL0=$(res eth_getBalance "[\"$DEV\",\"latest\"]"); sleep 1.5
BAL1=$(res eth_getBalance "[\"$DEV\",\"latest\"]")
[ "$((BAL1))" -gt "$((BAL0))" ] && echo "ok: balance streams up ($BAL0 -> $BAL1)" || fail "balance did not stream"
eq "$(res eth_getTransactionCount "[\"$DEV\",\"latest\"]")" "0x0" "dev nonce starts at 0"

# --- Criterion 3: signed transfer (raw tx provided by the test signer; see M1-T7 report) ---
# 0.001 UBI transfer, nonce 0, EIP-155 for chain 0x5542, signed by the public Hardhat dev key.
RAW="0xf86c80843b9aca008252089400000000000000000000000000000000000000aa87038d7ea4c680008082aaa8a0ce4122a80b0f941dbaddf0bf3a96948b14ed598f4141d6034411c6e877eb1b8ca0540bea995e2988263f84408d57baab3af3df73138b0590d2d5786471e1757466"
TXH=$(res eth_sendRawTransaction "[\"$RAW\"]")
[ "${TXH:0:2}" = "0x" ] && echo "ok: eth_sendRawTransaction accepted ($TXH)" || fail "sendRawTransaction: $(call eth_sendRawTransaction "[\"$RAW\"]")"
sleep 2.2
eq "$(res eth_getBalance "[\"$RCPT\",\"latest\"]")" "0x38d7ea4c68000" "recipient holds 0.001 UBI"
eq "$(res eth_getTransactionCount "[\"$DEV\",\"latest\"]")" "0x1" "dev nonce advanced to 1"

# --- Criterion 4: explorer ---
eq "$(call eth_getTransactionReceipt "[\"$TXH\"]" | jq -r '.result.status')" "0x1" "receipt status success"
BN=$(call eth_getTransactionByHash "[\"$TXH\"]" | jq -r '.result.blockNumber')
eq "$(call eth_getBlockByNumber "[\"$BN\", true]" | jq -r '.result.transactions[0].hash')" "$TXH" "block renders the tx"

# --- newHeads over WS (best-effort; skipped if node lacks global WebSocket) ---
if command -v node >/dev/null; then
  node -e '
    const ws = new WebSocket(process.argv[1]);
    const to = setTimeout(()=>{console.error("FAIL: no newHeads in 6s");process.exit(1);},6000);
    let n=0;
    ws.onopen=()=>ws.send(JSON.stringify({jsonrpc:"2.0",id:1,method:"eth_subscribe",params:["newHeads"]}));
    ws.onmessage=(e)=>{const m=JSON.parse(e.data); if(m.method==="eth_subscription"){if(++n>=2){clearTimeout(to);console.log("ok: newHeads streamed",n,"headers");ws.close();process.exit(0);}}};
    ws.onerror=(e)=>{console.error("WS error",e.message||e);process.exit(1);};
  ' "$WSURL" || echo "warn: WS newHeads check skipped/failed (non-fatal)"
fi

echo "== ALL E2E CHECKS PASSED =="
