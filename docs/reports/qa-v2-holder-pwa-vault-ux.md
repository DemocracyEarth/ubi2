# QA gate — V2 holder PWA vault UX

**Result: GREEN for the production-disabled testnet slice. Physical-device admission remains OPEN.**

## Acceptance coverage

- Exact flag/environment/network gates hide or disable the product on unset flags, production Self, local chains and
  mainnets.
- WebAuthn tests cover registration PRF output, registration-to-assertion fallback, exact returned credential id,
  32-byte output, secure-context rejection and unenrolled-credential rejection.
- The real PoH production build exercises enrollment, fresh unlock, atomic second passkey, encrypted backup,
  fresh-profile restore, force-close/reload relock, rapid duplicate-action suppression, late completion after an
  ignored native abort, cancellation and wallet-account invalidation.
- The browser suite verifies no rehearsal plaintext or account appears in the IndexedDB record/name, no recovery key
  appears in IndexedDB/Web Storage/package ciphertext, Cache Storage stays empty, and PWA control succeeds.
- Strict payload/recovery parsers reject extra keys, `productionEligible: true`, wrong accounts and wrong RP ids.
- Existing PoH product tests and SDK/app typechecks remain green.

## Commands observed locally

```text
pnpm --filter @ubi2/sdk typecheck                         PASS
pnpm --filter @ubi2/proofofhumanity typecheck            PASS
pnpm --filter @ubi2/proofofhumanity test:product         PASS
pnpm --filter @ubi2/proofofhumanity test:pwa             PASS (1 production-build Chromium test)
pnpm --filter @ubi2/proofofhumanity test:contracts       PASS
pnpm test:v2-vault-contract                              PASS
pnpm test:v2-holder-refresh                              PASS
pnpm test:v2-holder-refresh-wasm                         PASS
pnpm test:v2-holder-browser                              PASS (4 production-header Chromium tests)
pnpm -r typecheck                                        PASS
pnpm -r build                                            PASS (existing wallet lint warnings only)
```

The Chromium test uses an API-faithful deterministic PRF double so it can be repeatable in CI. It is not native
authenticator or physical-mobile evidence. The release host had neither an iOS nor Android physical-device lane;
the honest inventory is committed and the physical drill remains required before any production admission claim.

## Gate decision

No blocker exists for merging testnet-only, production-ineligible UX. This report does not mark the larger holder
task Done and does not satisfy representative physical-device, independent browser or cryptographic audit gates.
