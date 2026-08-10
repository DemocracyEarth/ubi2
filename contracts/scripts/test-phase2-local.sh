#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
task_tmp="$(mktemp -d)"
anvil_pid=""

if ! git check-ignore -q broadcast/Deploy.s.sol/84532/dry-run/run-latest.json; then
  echo "ERROR: Foundry dry-run broadcast artifacts are not git-ignored" >&2
  exit 1
fi

cleanup() {
  if [[ -n "$anvil_pid" ]]; then
    kill "$anvil_pid" >/dev/null 2>&1 || true
    wait "$anvil_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$task_tmp"
}
trap cleanup EXIT

wallet_dir="$task_tmp/keystores"
password_file="$task_tmp/password"
mkdir "$wallet_dir"
umask 077
printf '%s\n' 'phase2-ci-only' >"$password_file"

cast wallet new "$wallet_dir" deployer --unsafe-password phase2-ci-only >/dev/null
cast wallet new "$wallet_dir" issuer --unsafe-password phase2-ci-only >/dev/null

deployer_keystore="$wallet_dir/deployer"
issuer_keystore="$wallet_dir/issuer"
deployer_address="$(cast wallet address --keystore "$deployer_keystore" --password-file "$password_file")"
issuer_address="$(cast wallet address --keystore "$issuer_keystore" --password-file "$password_file")"

anvil_port="${PHASE2_ANVIL_PORT:-18545}"
rpc_url="http://127.0.0.1:$anvil_port"
anvil --port "$anvil_port" --silent >"$task_tmp/anvil.log" 2>&1 &
anvil_pid=$!

for _ in $(seq 1 50); do
  if cast chain-id --rpc-url "$rpc_url" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
[[ "$(cast chain-id --rpc-url "$rpc_url")" == "31337" ]]

cast rpc anvil_setBalance "$deployer_address" 0x3635C9ADC5DEA00000 --rpc-url "$rpc_url" >/dev/null

export LOCAL_RPC_URL="$rpc_url"
export POH_ISSUER="$issuer_address"
export POH_OWNER="$deployer_address"
export DEPLOY_PREDICATE=true
export DEPLOYER_KEYSTORE="$deployer_keystore"
export ISSUER_KEYSTORE="$issuer_keystore"
export DEPLOYER_PASSWORD_FILE="$password_file"
export ISSUER_PASSWORD_FILE="$password_file"
export FOUNDRY_BROADCAST="$task_tmp/broadcast"
export FOUNDRY_CACHE_PATH="$task_tmp/cache"

insecure_password_file="$task_tmp/insecure-password"
printf '%s\n' 'phase2-ci-only' >"$insecure_password_file"
chmod 0644 "$insecure_password_file"
if DEPLOYER_PASSWORD_FILE="$insecure_password_file" \
  "$SCRIPT_DIR/phase2.sh" preflight local >/dev/null 2>&1; then
  echo "ERROR: Phase 2 wrapper accepted a group/world-readable password file" >&2
  exit 1
fi
if PRIVATE_KEY=raw-key-must-be-rejected \
  "$SCRIPT_DIR/phase2.sh" preflight local >/dev/null 2>&1; then
  echo "ERROR: Phase 2 wrapper accepted a raw private-key environment variable" >&2
  exit 1
fi
if "$SCRIPT_DIR/phase2.sh" preflight ethereum-mainnet >/dev/null 2>&1; then
  echo "ERROR: Phase 2 wrapper accepted a mainnet target" >&2
  exit 1
fi
if "$SCRIPT_DIR/phase2.sh" preflight worldchain-mainnet >/dev/null 2>&1; then
  echo "ERROR: Phase 2 wrapper accepted World Chain mainnet" >&2
  exit 1
fi
if "$SCRIPT_DIR/phase2.sh" deploy local >/dev/null 2>&1; then
  echo "ERROR: Phase 2 wrapper broadcast without an exact confirmation" >&2
  exit 1
fi

export PHASE2_BROADCAST_CONFIRM=local:31337
"$SCRIPT_DIR/phase2.sh" deploy local
"$SCRIPT_DIR/phase2.sh" e2e local

echo "Phase 2 local deployment tooling rehearsal PASS"
