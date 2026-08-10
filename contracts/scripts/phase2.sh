#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$CONTRACTS_DIR"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: ./scripts/phase2.sh <preflight|simulate|deploy|e2e> <network>

Networks:
  base-sepolia       chain 84532
  ethereum-sepolia   chain 11155111
  celo-sepolia       chain 11142220 (replaces end-of-life Alfajores)
  robinhood-testnet  chain 46630
  worldchain-sepolia chain 4801
  local              chain 31337; deterministic tooling rehearsal only

The script accepts encrypted Foundry keystores only. It rejects raw private-key environment
variables, validates the RPC chain ID, and refuses every mainnet chain. `deploy` additionally
requires PHASE2_BROADCAST_CONFIRM=<network>:<chainId>.

See PHASE2.md and phase2.env.example.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "$name is required"
}

require_private_file() {
  local file="$1" label="$2" mode
  [[ -f "$file" ]] || die "$label does not exist"
  mode="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null)"
  case "$mode" in
    400 | 600) ;;
    *) die "$label must be owner-readable only (mode 0400 or 0600); got $mode" ;;
  esac
}

normalise_address() {
  cast to-check-sum-address "$1" 2>/dev/null || die "invalid address: $1"
}

assert_address_eq() {
  local actual expected label
  actual="$(normalise_address "$1")"
  expected="$(normalise_address "$2")"
  label="$3"
  [[ "$actual" == "$expected" ]] || die "$label mismatch: got $actual; expected $expected"
}

while IFS= read -r variable_name; do
  case "$variable_name" in
    *PRIVATE_KEY* | *MNEMONIC*)
      [[ -z "${!variable_name:-}" ]] ||
        die "$variable_name must not be set; use an encrypted keystore"
      ;;
  esac
done < <(compgen -e)

action="${1:-}"
network="${2:-}"
if [[ -z "$action" || -z "$network" ]]; then
  usage
  exit 2
fi

case "$action" in
  preflight | simulate | deploy | e2e) ;;
  -h | --help | help)
    usage
    exit 0
    ;;
  *) die "unsupported action: $action" ;;
esac

case "$network" in
  base-sepolia)
    chain_id=84532
    rpc_env=BASE_SEPOLIA_RPC_URL
    verifier=etherscan
    ;;
  ethereum-sepolia)
    chain_id=11155111
    rpc_env=ETHEREUM_SEPOLIA_RPC_URL
    verifier=etherscan
    ;;
  celo-sepolia)
    chain_id=11142220
    rpc_env=CELO_SEPOLIA_RPC_URL
    verifier=etherscan
    ;;
  robinhood-testnet)
    chain_id=46630
    rpc_env=ROBINHOOD_TESTNET_RPC_URL
    verifier=blockscout
    verifier_url=https://explorer.testnet.chain.robinhood.com/api/
    ;;
  worldchain-sepolia)
    chain_id=4801
    rpc_env=WORLDCHAIN_TESTNET_RPC_URL
    verifier=etherscan
    ;;
  local)
    chain_id=31337
    rpc_env=LOCAL_RPC_URL
    verifier=none
    ;;
  *) die "unsupported network '$network'; mainnet and deprecated testnets are intentionally refused" ;;
esac

require_command cast
require_command forge
require_command git
require_command node
require_env "$rpc_env"
require_env POH_ISSUER
require_env POH_OWNER

rpc_url="${!rpc_env}"
[[ "${DEPLOY_PREDICATE:-}" == "true" ]] || die "DEPLOY_PREDICATE must be exactly true"

DEPLOYER_ACCOUNT="${DEPLOYER_ACCOUNT:-poh-testnet-deployer}"
ISSUER_ACCOUNT="${ISSUER_ACCOUNT:-poh-testnet-issuer}"

deployer_wallet_args=()
issuer_wallet_args=()
if [[ -n "${DEPLOYER_KEYSTORE:-}" ]]; then
  [[ -f "$DEPLOYER_KEYSTORE" ]] || die "DEPLOYER_KEYSTORE does not exist"
  deployer_wallet_args+=(--keystore "$DEPLOYER_KEYSTORE")
else
  deployer_wallet_args+=(--account "$DEPLOYER_ACCOUNT")
fi
if [[ -n "${ISSUER_KEYSTORE:-}" ]]; then
  [[ -f "$ISSUER_KEYSTORE" ]] || die "ISSUER_KEYSTORE does not exist"
  issuer_wallet_args+=(--keystore "$ISSUER_KEYSTORE")
else
  issuer_wallet_args+=(--account "$ISSUER_ACCOUNT")
fi
deployer_password_file="${DEPLOYER_PASSWORD_FILE:-${WALLET_PASSWORD_FILE:-}}"
issuer_password_file="${ISSUER_PASSWORD_FILE:-${WALLET_PASSWORD_FILE:-}}"
if [[ -n "$deployer_password_file" ]]; then
  require_private_file "$deployer_password_file" "deployer password file"
  deployer_wallet_args+=(--password-file "$deployer_password_file")
fi
if [[ -n "$issuer_password_file" ]]; then
  require_private_file "$issuer_password_file" "issuer password file"
  issuer_wallet_args+=(--password-file "$issuer_password_file")
fi

actual_chain_id="$(cast chain-id --rpc-url "$rpc_url")"
[[ "$actual_chain_id" == "$chain_id" ]] ||
  die "$network RPC returned chain ID $actual_chain_id; expected $chain_id"

issuer_expected="$(normalise_address "$POH_ISSUER")"
owner_expected="$(normalise_address "$POH_OWNER")"
zero_address=0x0000000000000000000000000000000000000000
[[ "$issuer_expected" != "$zero_address" ]] || die "POH_ISSUER must not be zero"
[[ "$owner_expected" != "$zero_address" ]] || die "POH_OWNER must not be zero"

deployer_address="$(cast wallet address "${deployer_wallet_args[@]}")"
issuer_address="$(cast wallet address "${issuer_wallet_args[@]}")"
assert_address_eq "$issuer_address" "$issuer_expected" "issuer keystore address"

deployer_balance="$(cast balance "$deployer_address" --rpc-url "$rpc_url")"
[[ "$deployer_balance" != "0" ]] || die "deployer has no gas funds on $network"

commit="$(git rev-parse HEAD)"
if [[ "$network" != "local" && -n "$(git status --porcelain)" ]]; then
  die "testnet deploys require a clean git worktree"
fi

echo "Phase 2 preflight PASS"
echo "  network  : $network ($chain_id)"
echo "  commit   : $commit"
echo "  deployer : $(normalise_address "$deployer_address")"
echo "  issuer   : $issuer_expected"
echo "  owner    : $owner_expected"
echo "  predicate: enabled; prover must remain unset"
if [[ "$(normalise_address "$deployer_address")" == "$issuer_expected" ]]; then
  echo "WARNING: deployer and issuer are the same testnet account; separate roles are recommended" >&2
fi

if [[ "$action" == "preflight" ]]; then
  exit 0
fi

if [[ "$action" == "simulate" || "$action" == "deploy" ]]; then
  export POH_ISSUER="$issuer_expected"
  export POH_OWNER="$owner_expected"
  export DEPLOY_PREDICATE=true

  forge_args=(
    script/Deploy.s.sol:Deploy
    --rpc-url "$rpc_url"
    "${deployer_wallet_args[@]}"
    -vvv
  )

  if [[ "$action" == "deploy" ]]; then
    expected_confirmation="$network:$chain_id"
    [[ "${PHASE2_BROADCAST_CONFIRM:-}" == "$expected_confirmation" ]] ||
      die "set PHASE2_BROADCAST_CONFIRM=$expected_confirmation to authorize this testnet broadcast"

    forge_args+=(--broadcast --slow)
    case "$verifier" in
      etherscan)
        require_env ETHERSCAN_API_KEY
        forge_args+=(--verify)
        ;;
      blockscout)
        forge_args+=(--verify --verifier blockscout --verifier-url "$verifier_url")
        ;;
      none) ;;
    esac
  fi

  forge build --sizes
  forge script "${forge_args[@]}"

  if [[ "$action" == "deploy" ]]; then
    broadcast_root="${FOUNDRY_BROADCAST:-broadcast}"
    manifest="$broadcast_root/Deploy.s.sol/$chain_id/run-latest.json"
    [[ -f "$manifest" ]] || die "Foundry broadcast manifest not found at $manifest"
    echo "Validated deployment manifest:"
    node "$SCRIPT_DIR/read-deployment.mjs" "$manifest" summary
  fi
  exit 0
fi

broadcast_root="${FOUNDRY_BROADCAST:-broadcast}"
manifest="$broadcast_root/Deploy.s.sol/$chain_id/run-latest.json"
[[ -f "$manifest" ]] || die "deploy first; broadcast manifest not found at $manifest"

renderer="$(node "$SCRIPT_DIR/read-deployment.mjs" "$manifest" renderer)"
poh="$(node "$SCRIPT_DIR/read-deployment.mjs" "$manifest" poh)"
predicate="$(node "$SCRIPT_DIR/read-deployment.mjs" "$manifest" predicate)"

assert_address_eq "$(cast call "$poh" 'issuer()(address)' --rpc-url "$rpc_url")" "$issuer_expected" "ProofOfHumanity.issuer"
assert_address_eq "$(cast call "$poh" 'owner()(address)' --rpc-url "$rpc_url")" "$owner_expected" "ProofOfHumanity.owner"
assert_address_eq "$(cast call "$poh" 'cardRenderer()(address)' --rpc-url "$rpc_url")" "$renderer" "ProofOfHumanity.cardRenderer"
assert_address_eq "$(cast call "$predicate" 'issuer()(address)' --rpc-url "$rpc_url")" "$issuer_expected" "PredicateVerifier.issuer"
assert_address_eq "$(cast call "$predicate" 'owner()(address)' --rpc-url "$rpc_url")" "$owner_expected" "PredicateVerifier.owner"
assert_address_eq "$(cast call "$predicate" 'prover()(address)' --rpc-url "$rpc_url")" "$zero_address" "PredicateVerifier.prover"

[[ "$(cast code "$renderer" --rpc-url "$rpc_url")" != "0x" ]] || die "renderer has no deployed bytecode"
[[ "$(cast code "$poh" --rpc-url "$rpc_url")" != "0x" ]] || die "ProofOfHumanity has no deployed bytecode"
[[ "$(cast code "$predicate" --rpc-url "$rpc_url")" != "0x" ]] || die "PredicateVerifier has no deployed bytecode"

recipient="${PHASE2_E2E_RECIPIENT:-$deployer_address}"
recipient="$(normalise_address "$recipient")"
epoch="$(cast call "$poh" 'currentEpoch()(uint32)' --rpc-url "$rpc_url")"
nullifier="$(cast keccak "ubi2-poh-phase2:$chain_id:$poh")"
token_before="$(cast call "$poh" 'tokenOfNullifier(uint256)(uint256)' "$nullifier" --rpc-url "$rpc_url")"
[[ "$token_before" == "0" ]] || die "deterministic e2e nullifier is already used by token $token_before"

voucher="($recipient,$nullifier,$epoch)"
digest="$(cast call "$poh" 'hashVoucher((address,uint256,uint32))(bytes32)' "$voucher" --rpc-url "$rpc_url")"
signature="$(cast wallet sign "$digest" --no-hash "${issuer_wallet_args[@]}")"

mint_tx="$(
  cast send "$poh" 'mintWithVoucher((address,uint256,uint32),bytes)' "$voucher" "$signature" \
    --rpc-url "$rpc_url" "${deployer_wallet_args[@]}" --async
)"
status="$(cast receipt "$mint_tx" status --rpc-url "$rpc_url" --confirmations 1)"
case "$status" in
  1 | 0x1 | success | "1 (success)") ;;
  *) die "mint transaction failed with status '$status': $mint_tx" ;;
esac

token_id="$(cast call "$poh" 'tokenOfNullifier(uint256)(uint256)' "$nullifier" --rpc-url "$rpc_url")"
[[ "$token_id" != "0" ]] || die "mint did not allocate a token"
assert_address_eq "$(cast call "$poh" 'ownerOf(uint256)(address)' "$token_id" --rpc-url "$rpc_url")" "$recipient" "token owner"
[[ "$(cast call "$poh" 'isValid(uint256)(bool)' "$token_id" --rpc-url "$rpc_url")" == "true" ]] || die "minted token is not valid"
[[ "$(cast call "$poh" 'locked(uint256)(bool)' "$token_id" --rpc-url "$rpc_url")" == "true" ]] || die "minted token is not soulbound"

if cast call "$poh" 'mintWithVoucher((address,uint256,uint32),bytes)' "$voucher" "$signature" --rpc-url "$rpc_url" >/dev/null 2>&1; then
  die "voucher replay unexpectedly succeeded"
fi
if cast call "$poh" 'transferFrom(address,address,uint256)' "$recipient" "$issuer_expected" "$token_id" \
  --from "$recipient" --rpc-url "$rpc_url" >/dev/null 2>&1; then
  die "soulbound transfer unexpectedly succeeded"
fi

echo "Phase 2 e2e PASS"
echo "  network            : $network ($chain_id)"
echo "  PoHCardRenderer     : $renderer"
echo "  ProofOfHumanity     : $poh"
echo "  PredicateVerifier   : $predicate"
echo "  mint tx             : $mint_tx"
echo "  token id            : $token_id"
echo "  valid / locked      : true / true"
echo "  replay / transfer   : reverted / reverted"
echo "  predicate prover    : unset"
