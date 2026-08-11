#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: ./scripts/phase2-all.sh <preflight|simulate|e2e> [network ...]

Runs a non-broadcast Phase 2 gate across all five supported testnets, or across
the explicitly listed networks. This aggregate helper intentionally refuses
deploy: every testnet broadcast must still use phase2.sh with its exact
PHASE2_BROADCAST_CONFIRM=<network>:<chainId> value.

Default networks:
  base-sepolia ethereum-sepolia celo-sepolia robinhood-testnet worldchain-sepolia
EOF
}

action="${1:-}"
case "$action" in
  preflight | simulate | e2e) shift ;;
  -h | --help | help)
    usage
    exit 0
    ;;
  deploy)
    echo "ERROR: aggregate broadcasts are forbidden; deploy one testnet at a time with phase2.sh" >&2
    exit 1
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if (($# > 0)); then
  networks=("$@")
else
  networks=(base-sepolia ethereum-sepolia celo-sepolia robinhood-testnet worldchain-sepolia)
fi

failures=()
for network in "${networks[@]}"; do
  printf '\n=== Phase 2 %s: %s ===\n' "$action" "$network"
  if "$SCRIPT_DIR/phase2.sh" "$action" "$network"; then
    printf '%s %s PASS\n' "$network" "$action"
  else
    failures+=("$network")
    printf '%s %s FAIL\n' "$network" "$action" >&2
  fi
done

if ((${#failures[@]} > 0)); then
  printf '\nERROR: Phase 2 %s failed for: %s\n' "$action" "${failures[*]}" >&2
  exit 1
fi

printf '\nPhase 2 %s PASS on %s\n' "$action" "${networks[*]}"
