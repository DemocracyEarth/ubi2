# Sponsored PoH minting — testnet staging runbook

This profile enables sponsored minting only on Base Sepolia (`84532`). It keeps every mainnet
deployment zero-addressed and every mainnet chain id out of `POH_SPONSOR_TESTNET_CHAIN_IDS`. The
application also independently rejects any chain classified as `mainnet` or `local` before RPC or
sponsor-balance access.

The rehearsal proves a real transaction from an isolated sponsor to the deployed PoH contract and
a real soulbound credential on a fresh, unfunded recipient. Its issuer voucher uses a synthetic,
uniquely named staging nullifier; it is not evidence that a human completed a Self passport scan.
The final phone/passport acceptance check remains human-in-the-loop and must use a different fresh
credential account.

The public receipt, pre/post account state, exact sponsor spend, and monitor result from the
2026-08-25 rehearsal are checked in as
[`evidence/base-sepolia-sponsored-mint-2026-08-25.json`](evidence/base-sepolia-sponsored-mint-2026-08-25.json).

## 1. Topology and account policy

Run one sticky Node replica on a private listener. Terminate TLS at a single trusted ingress and
block direct access to the Node port with the host firewall/security group. Install
[`nginx-sponsor-staging.conf.example`](nginx-sponsor-staging.conf.example) at that ingress after
replacing the example hostname and TLS paths. If another CDN/load balancer sits in front, accept
traffic only from its exact published ranges and configure it to overwrite, never append,
`X-Forwarded-For` before enabling `real_ip_header` in nginx.

Create a new random sponsor in the deployment secret manager. It must not equal the credential
recipient, PoH issuer, contract owner, deployer, or any application authority. Fund it with exactly
`0.002` Base Sepolia ETH for the first rehearsal; do not use a production-value asset. The staging
caps in [`staging.env.example`](staging.env.example) reserve `0.001`, flag balances above `0.005`,
and alert after `0.0005` spent in a UTC day.

Inject `POH_SPONSOR_PRIVATE_KEY` only into the runtime process. Do not put it in git, shell history,
container build arguments/layers, `NEXT_PUBLIC_*`, telemetry, or a support transcript. The included
rehearsal wrapper accepts encrypted Foundry keystores and password files and passes the decrypted
sponsor key through an anonymous pipe to the Node child process without writing or printing it.

## 2. Edge quotas

The example ingress applies independent per-source limits to `POST` (2/minute, burst 2) and receipt
recovery `GET` (12/minute, burst 4), plus two concurrent requests per source. Configure the edge/WAF
with an additional aggregate quota of **10 POST requests per UTC day** for this staging origin. The
app's chain-wide `POH_SPONSOR_DAILY_TX_LIMIT=10` is process-local defense in depth, not the distributed
counter. Alert on any 429 burst, sponsor-route 5xx, or Node restart.

Verify from an external client that a forged `X-Forwarded-For` value is replaced in the upstream
request log and that the Node listener cannot be reached directly. Log only request id, status,
latency, chain id and public transaction hash; redact cookies, `x-poh-session`, request headers and
all environment values.

## 3. Spend and reserve alarms

Copy [`staging.env.example`](staging.env.example) into the deployment's secret/config system, confirm
the checked-in public sponsor address and funding block, and create the state file directory with mode
`0700`. Set `POH_SPONSOR_MONITOR_START_BLOCK` to the successful funding receipt block. Seed the
read-only monitor immediately after funding and before opening ingress:

```sh
set -a
. /etc/ubi2/poh-sponsor-staging.env
set +a
pnpm --filter @ubi2/proofofhumanity sponsor:monitor
```

Run that command every minute. Exit `0` means healthy, `2` means a reserve, overfunding, or daily
spend alert, and `1` means monitoring failed. Page on both nonzero statuses. The state contains only
the public address, block cursor, UTC day and cumulative native-token spend; keep it on durable local
storage. The monitor scans every outgoing sponsor receipt for actual gas and successful value spend.
It refuses to skip a gap larger than 500 blocks, so monitoring outages fail loudly instead of
silently losing spend history.

## 4. Live unfunded-account rehearsal

Prepare three distinct encrypted Foundry keystores: the fresh low-balance sponsor, the existing
testnet issuer, and a new recipient. Keep their password files separate and mode `0600`. Confirm the
recipient has balance `0`, nonce `0`, no bytecode, and PoH `balanceOf == 0`. Then run:

```sh
export POH_SPONSOR_KEYSTORE=/secure/poh-staging-sponsor
export POH_SPONSOR_PASSWORD_FILE=/secure/poh-staging-sponsor.password
export POH_ISSUER_KEYSTORE=/secure/poh-testnet-issuer
export POH_ISSUER_PASSWORD_FILE=/secure/poh-testnet-issuer.password
export POH_RECIPIENT_KEYSTORE=/secure/poh-staging-recipient
export POH_RECIPIENT_PASSWORD_FILE=/secure/poh-staging-recipient.password
export POH_REHEARSAL_RPC_URL=https://your-private-base-sepolia-rpc.example
export POH_REHEARSAL_RUN_ID=change-ticket-and-timestamp
ops/proofofhumanity/rehearse-sponsored-mint.sh
```

The command fails before spending unless the chain is Base Sepolia, the contract issuer matches,
all roles are distinct, the recipient is pristine, the account/voucher/proof fields bind exactly,
the gas/fee/reserve caps pass, and the contract simulation succeeds. It then uses the production
executor and receipt verifier. Save only the JSON report: it contains public addresses, balances,
transaction/block hashes and verified token post-state, never a private key.

If receipt verification is temporarily unavailable after submission, the JSON response includes
the public transaction hash and exits `2`. Set `POH_REHEARSAL_TRANSACTION_HASH` to that hash and
rerun with the same run id; recovery re-reads the historical pre-state and receipt without sending
another transaction.

## 5. Promotion and rollback gates

- Receipt `from` is the isolated sponsor and `to` is the registered Base Sepolia PoH contract.
- `HumanityMinted`, `tokenOfNullifier`, `ownerOf`, `isValid`, and `locked` agree at the receipt block.
- The recipient still has native balance `0` and nonce `0`, but PoH balance `1`.
- Monitor reports no alert after the transaction, and ingress quotas produce 429 at the documented limits.
- A mainnet chain id is absent from runtime configuration and rejected by the application test suite.
- Complete one separate real Self staging verification on a fresh account before calling the rollout user-ready.

To roll back, remove both `POH_SPONSOR_PRIVATE_KEY` and `POH_SPONSOR_TESTNET_CHAIN_IDS` and restart
the single Node replica. The route returns disabled without either variable. Close ingress access,
retain public receipt evidence, and rotate/sweep the testnet sponsor according to the incident ticket.
