---
name: deploy-poh-contracts
description: Deploy the Proof of Humanity contracts (ProofOfHumanity soulbound SBT + on-chain card renderer + optional PredicateVerifier) to EVM chains — Base, Ethereum, Celo, or any EVM chain — with Foundry, verify them on the block explorer, and wire the addresses into the proofofhumanity.org app. Also explains why UBI Chain (ubi2 native) needs NO contract deploy. Use whenever deploying, redeploying, or adding a chain for the PoH contracts.
---

# Deploy Proof of Humanity contracts (EVM chains)

This skill deploys the on-chain half of **proofofhumanity.org**. The same bytecode goes to
every EVM chain; each chain gets its own EIP-712 domain automatically (from its `chainId` +
the deployed address), so a voucher signed for one chain can't be replayed on another.

**Golden rule:** the `ProofOfHumanity.issuer()` on every chain MUST equal the address of the
app's `ISSUER_PRIVATE_KEY`. If they don't match, no mint will ever verify.

---

## What gets deployed

Repo: `/Users/santisiri/AI/ubi2/contracts` (Foundry, solc 0.8.28). Deploy order + args:

| # | Contract | Constructor | Purpose | Required? |
|---|----------|-------------|---------|-----------|
| 1 | `PoHCardRenderer` | `()` — no args | Stateless on-chain SVG card for `tokenURI`. `Countries` is an inlined internal library — **no library linking needed**. | Recommended |
| 2 | `ProofOfHumanity` | `(address owner, address issuer)` | The ERC-721 + ERC-5192 soulbound credential. `mintWithVoucher` accepts an EIP-712 voucher signed by `issuer`. `owner` can `setIssuer` / `setCardRenderer`. | **Yes** |
| 3 | `PredicateVerifier` | `(address owner, address issuer)` | Predicate layer. Ships the v1 issuer path **and** the ADR-0009 prover seam (`consumeWithProof`/`setPredicateProver`), so this deployment is **final** — v1.5/v2 activate by config, not redeploy. | Only if using predicate gating |
| 4 | `SybilResistantVote` | `(poh, pv, requiredPredicate, context)` | Demo consumer only — **do not deploy to production**. | No |

The script `contracts/script/Deploy.s.sol` (`Deploy`) does 1→3: deploys the renderer, deploys
`ProofOfHumanity` (owned by the deployer so it can wire the renderer, then hands ownership to
`POH_OWNER`), and optionally `PredicateVerifier`.

> **This deployment is final (ADR-0009).** `PredicateVerifier` deploys with its `prover` **unset**,
> so the v1 issuer path is active immediately. When the trustless prover ships (v1.5 Self-ZK, then
> v2 anonymous credential), the owner calls `setPredicateProver(<prover>)` on the **same** deployed
> address — no redeploy, no consumer migration, no `ProofOfHumanity` change. Deploying now does not
> lock you into v1.

---

## Prerequisites (once)

1. **Foundry** installed (`forge --version`). Restore pinned deps (lib/ is git-ignored):
   ```bash
   cd contracts
   forge install \
     OpenZeppelin/openzeppelin-contracts@cab19933c33c2ad1d4c7a84864a3601dddfd16f3 \
     foundry-rs/forge-std@bf647bd6046f2f7da30d0c2bf435e5c76a780c1b \
     --no-git
   forge build && forge test   # must be green before any deploy
   ```
   These immutable commits correspond to OpenZeppelin `v5.7.0` and forge-std `v1.16.2`.
2. **A deployer account with gas funds** on each target chain. Store it as an ENCRYPTED
   keystore — never a plaintext private key on disk or in a command:
   ```bash
   cast wallet import poh-deployer --interactive   # paste the deployer private key once
   ```
   Then every command uses `--account poh-deployer` (prompts for the password). Fund this
   address with the chain's gas token (ETH on Base/Ethereum, CELO on Celo). The full stack is
   ~5M gas (~0.005 ETH on Base/Celo; can be significant on Ethereum L1 — deploy at low gas).
3. **The issuer address** — the address of the app's `ISSUER_PRIVATE_KEY`
   (`cast wallet address --account <issuer-keystore>`, or derive from the key). This is the
   value for `POH_ISSUER`. The issuer key itself is NOT needed for deployment (it only signs
   vouchers at runtime, off-chain).
4. **The owner** — ideally a multisig (Safe). Set `POH_OWNER` to it; it can later rotate the
   issuer via `setIssuer`. Defaults to the deployer if unset.
5. **Block-explorer API keys** for source verification (Basescan / Etherscan / Celoscan).

## Mandatory Phase 2 testnet gate

Before any mainnet work, follow [`contracts/PHASE2.md`](../../../contracts/PHASE2.md) and use
`contracts/scripts/phase2.sh`. The wrapper accepts encrypted Foundry keystores only, refuses mainnet
chain IDs, validates the RPC chain ID and signer/issuer wiring, defaults to simulation, and requires an
exact network-specific confirmation before testnet broadcast.

The current testnet matrix is Base Sepolia (`84532`), Ethereum Sepolia (`11155111`), Celo Sepolia
(`11142220`), Robinhood Chain Testnet (`46630`), and World Chain Sepolia (`4801`). Celo Alfajores
(`44787`) reached end-of-life on 2025-09-30 and must not be used for a new dry-run.

### Recommended: add chain configs to `contracts/foundry.toml`

```toml
[rpc_endpoints]
base     = "${BASE_RPC_URL}"
ethereum = "${ETH_RPC_URL}"
celo     = "${CELO_RPC_URL}"

[etherscan]
base     = { key = "${BASESCAN_API_KEY}",  url = "https://api.basescan.org/api",  chain = 8453 }
ethereum = { key = "${ETHERSCAN_API_KEY}", url = "https://api.etherscan.io/api",  chain = 1 }
celo     = { key = "${CELOSCAN_API_KEY}",   url = "https://api.celoscan.io/api",   chain = 42220 }
```
With this, commands can use `--rpc-url base --verify` and Foundry resolves the explorer.

---

## Deploy — the general command

```bash
cd contracts
export POH_ISSUER=0x...            # MUST equal the app's ISSUER_PRIVATE_KEY address
export POH_OWNER=0x...             # multisig recommended; omit to use the deployer
export DEPLOY_PREDICATE=true       # omit/false to skip PredicateVerifier

forge script script/Deploy.s.sol:Deploy \
  --rpc-url <chain> \
  --account poh-deployer \
  --broadcast \
  --verify \
  -vvv
```

**Always dry-run first** (drop `--broadcast --verify`) to see the simulated addresses + gas.
The run prints `PoHCardRenderer`, `ProofOfHumanity`, `PredicateVerifier`, `owner`, `issuer` —
record them (they also land in `contracts/broadcast/Deploy.s.sol/<chainId>/run-latest.json`).

---

## Per-chain specifics

### Base — chainId `8453`
- RPC: `https://mainnet.base.org` (or an Alchemy/Ankr endpoint for reliability).
- Gas token: **ETH** (on Base). Explorer: https://basescan.org · verify with `BASESCAN_API_KEY`.
```bash
export BASE_RPC_URL=https://mainnet.base.org
forge script script/Deploy.s.sol:Deploy --rpc-url "$BASE_RPC_URL" --account poh-deployer \
  --broadcast --verify --verifier etherscan --etherscan-api-key "$BASESCAN_API_KEY" \
  --verifier-url https://api.basescan.org/api -vvv
```

### Ethereum mainnet — chainId `1`
- RPC: an Alchemy/Infura URL (no reliable public mainnet RPC for broadcasting).
- Gas token: **ETH**. Explorer: https://etherscan.io · verify with `ETHERSCAN_API_KEY`.
- **Cost warning:** ~5M gas on L1 is real money — check `cast gas-price --rpc-url "$ETH_RPC_URL"`
  and deploy during a low-gas window.
```bash
export ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/<KEY>
forge script script/Deploy.s.sol:Deploy --rpc-url "$ETH_RPC_URL" --account poh-deployer \
  --broadcast --verify --etherscan-api-key "$ETHERSCAN_API_KEY" -vvv
```

### Celo — chainId `42220`
- RPC: `https://forno.celo.org`. Celo is now an Ethereum L2 but remains EVM-equivalent — the
  same bytecode + Foundry flow works unchanged.
- Gas token: **CELO** (fund the deployer with CELO). Explorer: https://celoscan.io · verify
  with `CELOSCAN_API_KEY`.
```bash
export CELO_RPC_URL=https://forno.celo.org
forge script script/Deploy.s.sol:Deploy --rpc-url "$CELO_RPC_URL" --account poh-deployer \
  --broadcast --verify --verifier etherscan --etherscan-api-key "$CELOSCAN_API_KEY" \
  --verifier-url https://api.celoscan.io/api -vvv
```

> Etherscan V2 note: a single Etherscan API key can verify across chains via the unified
> `https://api.etherscan.io/v2/api?chainid=<id>` endpoint. If you use it, pass that key and let
> Foundry pick the URL; the per-explorer keys above are the reliable fallback.

---

## Post-deploy — wire + verify (every chain)

1. **Confirm the issuer on-chain matches the app:**
   ```bash
   cast call <POH_ADDRESS> "issuer()(address)" --rpc-url <chain>   # == POH_ISSUER
   cast call <POH_ADDRESS> "cardRenderer()(address)" --rpc-url <chain>  # == renderer
   cast call <POH_ADDRESS> "owner()(address)" --rpc-url <chain>    # == POH_OWNER
   ```
2. **Record the address into the app env** (`apps/proofofhumanity/DEPLOY.md` matrix). The app
   currently wires Base / Celo / Optimism + local:
   - `NEXT_PUBLIC_BASE_POH=<base address>`
   - `NEXT_PUBLIC_CELO_POH=<celo address>`
   - `NEXT_PUBLIC_OP_POH=<optimism address>`
   - **Ethereum is not in `apps/proofofhumanity/app/config.ts` yet** — to offer minting on
     mainnet, add an Ethereum entry to the `CHAINS` array (chainId 1, an RPC, a
     `NEXT_PUBLIC_ETH_POH` env) mirroring the Base entry.
   Redeploy the app after changing any `NEXT_PUBLIC_*` (they're baked in at build time).
3. **If you deployed `PredicateVerifier`**, record it for any predicate-gated consumer and set
   its issuer to the same address (`issuer()` should already equal `POH_ISSUER`).
4. **Verify the source** shows "Verified" on the explorer; if `--verify` failed mid-deploy,
   re-run just verification: `forge verify-contract <addr> src/ProofOfHumanity.sol:ProofOfHumanity --chain <id> --etherscan-api-key <key> --constructor-args $(cast abi-encode "constructor(address,address)" <owner> <issuer>)`.

---

## UBI Chain (ubi2 native) — no contract to deploy

**Do not run this skill for UBI Chain.** On ubi2, Proof of Humanity is **native to the L1
runtime**, not an EVM contract — there is nothing to `forge create`.

- **Where it lives:** the ubi2 node ships a genesis **HumanityHub** system contract (fixed
  address `0x…5048`, in `crates/runtime`) that answers the ERC-721 interface directly:
  `tokenId ↔ the human's address` (deterministic, injective), and the token **exists iff** that
  account's status is `Verified` — `Pending→Verified` emits `Transfer(0x0 → addr, tokenId)`,
  `Verified→Challenged` burns it. `ownerOf(tokenId)` agrees with `ubi_getHuman(addr).status`.
  It is soulbound by construction (bound to the human, not transferable).
- **How a human "mints" on ubi2:** instead of the EVM `mintWithVoucher` (a trusted issuer
  signature), a human submits their Self ZK passport proof via the runtime op
  **`submitZkPassportProof`**, which the node verifies **natively** with the in-runtime Groth16
  verifier against the mirrored Self identity-registry root. This is the **trustless** path
  that the EVM contracts leave as the `IHumanityProofVerifier` seam — on ubi2 it's the real
  thing, so **no issuer key is trusted** for native minting.
- **What it unlocks:** holding the native PoH token **gates the native UBI stream** — only
  Verified humans accrue the 1-UBI/hour emission, and PoH holders form the validator set. This
  is the whole point of ubi2: proof-of-humanity is the Sybil-resistance layer the basic income
  streams through.
- **"Deploying" to UBI Chain therefore means** shipping/upgrading the chain itself (genesis
  config: the HumanityHub + Groth16 verifier + the `proofofhumanity.org` Self scope), NOT
  deploying this Foundry package. See `crates/runtime` and the plan/roadmap for the runtime
  work (EC-C7 reconciliation, the native verifier flip).
- **In the app**, UBI Chain appears in the mint picker (green) like any chain, but its mint
  path is the native submit-proof flow against the ubi2 RPC + the native PoH address — not the
  EVM voucher path. Wire the ubi2 RPC/address when the devnet/mainnet is live.

---

## Safety checklist

- [ ] `forge test` green before deploying.
- [ ] Deployer key in an encrypted keystore (`--account`), never plaintext; funded with the
      chain's gas token.
- [ ] `POH_ISSUER` == the app's `ISSUER_PRIVATE_KEY` address (verify with `cast call issuer()`).
- [ ] `POH_OWNER` is a multisig you control (it can rotate the issuer).
- [ ] Dry-run (no `--broadcast`) reviewed before broadcasting.
- [ ] Deploy **once per chain**; record addresses in `DEPLOY.md` + the app env; never commit
      keys.
- [ ] Source verified on the explorer.
- [ ] Do **not** deploy `SybilResistantVote` (demo) to production.
