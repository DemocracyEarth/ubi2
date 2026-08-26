#!/usr/bin/env bash
set -euo pipefail
set +x
shopt -s nocasematch

die() {
  printf 'sponsored mint rehearsal: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local name="$1"
  local path="${!name:-}"
  [[ -n "$path" ]] || die "$name is required"
  [[ -f "$path" ]] || die "$name does not name a file"
}

require_value() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "$name is required"
}

for name in \
  POH_SPONSOR_KEYSTORE \
  POH_SPONSOR_PASSWORD_FILE \
  POH_ISSUER_KEYSTORE \
  POH_ISSUER_PASSWORD_FILE \
  POH_RECIPIENT_KEYSTORE \
  POH_RECIPIENT_PASSWORD_FILE; do
  require_file "$name"
done
for name in POH_REHEARSAL_RPC_URL POH_REHEARSAL_RUN_ID; do
  require_value "$name"
done

chain_id="84532"
poh="0x06BD253009F74ad934A4DaEac133b153d9Fe8029"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

sponsor="$(cast wallet address --keystore "$POH_SPONSOR_KEYSTORE" --password-file "$POH_SPONSOR_PASSWORD_FILE")"
issuer="$(cast wallet address --keystore "$POH_ISSUER_KEYSTORE" --password-file "$POH_ISSUER_PASSWORD_FILE")"
recipient="$(cast wallet address --keystore "$POH_RECIPIENT_KEYSTORE" --password-file "$POH_RECIPIENT_PASSWORD_FILE")"
live_issuer="$(cast call "$poh" 'issuer()(address)' --rpc-url "$POH_REHEARSAL_RPC_URL")"
live_owner="$(cast call "$poh" 'owner()(address)' --rpc-url "$POH_REHEARSAL_RPC_URL")"

[[ "$issuer" == "$live_issuer" ]] || die "issuer keystore does not match the live contract issuer"
[[ "$sponsor" != "$issuer" ]] || die "sponsor overlaps issuer"
[[ "$sponsor" != "$live_owner" ]] || die "sponsor overlaps owner"
[[ "$sponsor" != "$recipient" ]] || die "sponsor overlaps recipient"

epoch="$(cast call "$poh" 'currentEpoch()(uint32)' --rpc-url "$POH_REHEARSAL_RPC_URL")"
nullifier="$(cast keccak "ubi2-poh-sponsor-rehearsal:${chain_id}:${poh}:${POH_REHEARSAL_RUN_ID}")"
voucher="(${recipient},${nullifier},${epoch})"
digest="$(cast call "$poh" 'hashVoucher((address,uint256,uint32))(bytes32)' "$voucher" --rpc-url "$POH_REHEARSAL_RPC_URL")"
signature="$(cast wallet sign "$digest" --no-hash --keystore "$POH_ISSUER_KEYSTORE" --password-file "$POH_ISSUER_PASSWORD_FILE")"

IFS= read -r sponsor_password < "$POH_SPONSOR_PASSWORD_FILE" || [[ -n "${sponsor_password:-}" ]]
[[ -n "${sponsor_password:-}" ]] || die "sponsor password file is empty"
sponsor_account="$(basename "$POH_SPONSOR_KEYSTORE")"
sponsor_keystore_dir="$(dirname "$POH_SPONSOR_KEYSTORE")"

# The decrypted key travels only through this anonymous pipe into the child
# process environment. It is never an argument, file, stdout line, or log field.
CAST_UNSAFE_PASSWORD="$sponsor_password" \
  cast wallet decrypt-keystore "$sponsor_account" --keystore-dir "$sponsor_keystore_dir" | {
    IFS= read -r decrypted_line
    POH_SPONSOR_PRIVATE_KEY="${decrypted_line##*: }"
    [[ "$POH_SPONSOR_PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "decrypted sponsor key has an invalid shape"
    unset decrypted_line
    export POH_SPONSOR_PRIVATE_KEY
    export POH_SPONSOR_TESTNET_CHAIN_IDS="$chain_id"
    export POH_SPONSOR_MAX_GAS="${POH_SPONSOR_MAX_GAS:-350000}"
    export POH_SPONSOR_MAX_FEE_WEI="${POH_SPONSOR_MAX_FEE_WEI:-500000000000000}"
    export POH_SPONSOR_MIN_RESERVE_WEI="${POH_SPONSOR_MIN_RESERVE_WEI:-1000000000000000}"
    export POH_SPONSOR_CONFIRMATIONS="${POH_SPONSOR_CONFIRMATIONS:-1}"
    export POH_SPONSOR_RECEIPT_TIMEOUT_MS="${POH_SPONSOR_RECEIPT_TIMEOUT_MS:-90000}"
    export POH_SPONSOR_DAILY_TX_LIMIT="${POH_SPONSOR_DAILY_TX_LIMIT:-10}"
    export NEXT_PUBLIC_BASE_SEPOLIA_RPC_URL="$POH_REHEARSAL_RPC_URL"
    export POH_REHEARSAL_CHAIN_ID="$chain_id"
    export POH_REHEARSAL_RECIPIENT="$recipient"
    export POH_REHEARSAL_NULLIFIER="$nullifier"
    export POH_REHEARSAL_EPOCH="$epoch"
    export POH_REHEARSAL_VOUCHER_SIGNATURE="$signature"
    export POH_REHEARSAL_VOUCHER_SOURCE="synthetic-staging-voucher-no-passport-claim"
    if [[ -n "${POH_REHEARSAL_TRANSACTION_HASH:-}" ]]; then
      export POH_REHEARSAL_TRANSACTION_HASH
    fi
    cd "$repo_root"
    pnpm --filter @ubi2/proofofhumanity sponsor:rehearse
    unset POH_SPONSOR_PRIVATE_KEY
  }
unset sponsor_password
