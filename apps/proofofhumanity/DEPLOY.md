# Deploying PoH Quick Launch v1

`@ubi2/proofofhumanity` is a Next.js 15 SSR application. Quick Launch is deliberately limited to:

- Self proof verification;
- issuer-signed humanity voucher;
- wallet or sponsored soulbound mint;
- issuer-attested age, nationality, and sanctions-clear predicates;
- Base Sepolia (`84532`) only.

Mainnet, additional testnets, demo credentials, the v2 issuance bridge, custom predicate provers, and
the experimental holder vault are not release features. No code merge authorizes a mainnet deployment.

## Runtime topology

Run one sticky Node process behind TLS. `/api/self-verify` hands its result to the browser through a
bounded, ten-minute, process-local address/session store. Autoscaling or multiple replicas can send the
phone callback and browser poll to different processes and are therefore unsupported until a reviewed
shared encrypted store exists.

The issuer route needs the server-only `ISSUER_PRIVATE_KEY`. Inject it from the deployment secret
manager; never put it in a build argument, image layer, `NEXT_PUBLIC_*`, committed env file, terminal
transcript, or support message. The public address derived from that secret must be
`0x1D6cB99ff20223d730Ae5D4680EC5154B7FdAefe` for the current reviewed contracts.

Testnet sponsorship is optional and uses a separate, low-balance `POH_SPONSOR_PRIVATE_KEY`. It is not an
issuer, owner, deployer, or holder key. The sponsored endpoint accepts only chain ID `84532`, loads all
credential inputs from the verified session, simulates before signing, and applies gas, fee, reserve,
attempt, source, account, capability, and daily limits.

## Public configuration

Start from [`.env.example`](.env.example). The release-relevant inputs are:

| Variable | Requirement |
|---|---|
| `NEXT_PUBLIC_SELF_ENDPOINT` | public HTTPS callback ending exactly in `/api/self-verify`; no credentials, query, fragment, or loopback host |
| `NEXT_PUBLIC_SELF_ENV` | `staging` for Self test passports or `production` for real passports |
| `NEXT_PUBLIC_BASE_SEPOLIA_RPC_URL` | monitored public Base Sepolia RPC; the checked-in public endpoint is only a fallback |
| `NEXT_PUBLIC_BASE_SEPOLIA_POH` | reviewed `0x06BD253009F74ad934A4DaEac133b153d9Fe8029` |
| `NEXT_PUBLIC_BASE_SEPOLIA_PREDICATE` | reviewed `0x2051D33c2F10CDd3739324afc4C6fD957564a9D6` |
| `ISSUER_PRIVATE_KEY` | server secret injected from the approved secret path; its public address must match both contracts |
| `POH_SPONSOR_PRIVATE_KEY` | optional isolated testnet hot key |
| `POH_SPONSOR_TESTNET_CHAIN_IDS` | exactly `84532` when sponsorship is enabled |

All other sponsorship caps retain the conservative defaults shown in `.env.example`. Put matching edge
quotas and spend/reserve alerts at the trusted proxy. The application uses the first
`X-Forwarded-For` value, so the proxy must overwrite untrusted forwarding headers.

## Transaction-free preflight

With only public configuration loaded, run:

```shell
pnpm --filter @ubi2/proofofhumanity quick-launch:preflight
```

The command sends no transaction and loads no secret. It verifies the RPC chain ID, both bytecodes,
reviewed owner, shared reviewed issuer, zero predicate prover, Self environment, and exact public HTTPS
callback. It emits only public addresses and Boolean readiness. Any mismatch exits non-zero.

Observed on 2026-08-30 from the public Base Sepolia RPC, without a transaction:

- chain ID `84532`;
- both configured addresses have bytecode;
- both owners are `0x26250e47500943464290A77ae3508a3001d9B69d`;
- both issuers are `0x1D6cB99ff20223d730Ae5D4680EC5154B7FdAefe`;
- `PredicateVerifier.prover()` is zero.

That read-only observation does not prove that an app host, issuer secret path, sponsor, public callback,
or real Self journey is ready.

## Validation gate

Before deploying the application candidate:

```shell
pnpm --filter @ubi2/proofofhumanity test:quick-launch
pnpm --filter @ubi2/proofofhumanity test:contracts
pnpm --filter @ubi2/proofofhumanity typecheck
pnpm --filter @ubi2/proofofhumanity build
pnpm --filter @ubi2/proofofhumanity test:pwa
```

Also run the repository's full CI-equivalent Rust, interface, Solidity, SDK, operator, and cross-stack
gates. A synthetic Anvil voucher or the checked-in sponsored-mint rehearsal proves plumbing only; it is
not evidence of a completed Self passport verification.

## Complete Base Sepolia journey

Run this twice: once with Self staging/test passports, then with Self production and an authorized real
passport tester. Record no passport payload, private attribute, credential, QR payload, key, password, or
env content.

1. Load `/`, connect a dedicated credential wallet, and acknowledge the public-address warning.
2. Select 18+ or 21+ and nationality as needed. Confirm sanctions-clear is required.
3. Complete the Self flow on a physical phone and observe the callback succeed.
4. Confirm exactly one voucher exists and its chain ID/address match the pinned Base Sepolia PoH contract.
5. Mint with the isolated sponsor from an unfunded holder account, or mint with the holder wallet.
6. Observe a confirmed receipt, the expected `HumanityMinted`/`HumanityRefreshed` event, owner, nullifier
   mapping, `isValid == true`, and `locked == true` at the receipt block.
7. Confirm a repeated sponsored request returns the same evidence without a second transaction.
8. On `/verify`, create and contract-check `age>=18`, `age>=21` when selected,
   `nationality=<selected A3>`, a deliberately false nationality comparison, and `sanctions-clear`.
9. Confirm wrong subject, consumer, context, chain, verifier, signer, epoch, and nonce fail closed.
10. Close the tab and confirm the held v1 credential is gone.

## Exact external blocker checklist

- [ ] Public HTTPS application origin and exact Self callback URL.
- [ ] Self application configuration for staging and, separately, production.
- [ ] Approved single-replica Node host, TLS, sticky routing, trusted-proxy configuration, restart/5xx alerts,
      and log-redaction review.
- [ ] Approved issuer secret-manager path whose public address matches both reviewed contracts; do not provide
      the secret value to reviewers.
- [ ] If sponsorship is enabled: separate sponsor secret path, public sponsor address, bounded Base Sepolia
      funding, edge quotas, daily-spend alert, and reserve alert.
- [ ] Physical-phone staging tester and authorized real-passport production tester.
- [ ] Redacted evidence template and storage location for callback, receipt, contract-state, and predicate
      outcomes.
- [ ] Product/security approval that v1 predicates are issuer-attested, subject-wallet-linkable, and currently
      stored only in `sessionStorage` without passkey encryption.

Until every applicable item and both observed journeys pass, call the build a testable release candidate,
not a live-ready product.
