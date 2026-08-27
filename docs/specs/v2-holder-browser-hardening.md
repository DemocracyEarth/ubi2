# V2 holder browser hardening and recovery harness

- **Status:** implemented as production-disabled release evidence
- **Runtime:** [`apps/holder-browser-harness`](../../apps/holder-browser-harness)
- **Storage:** [`credential-vault-indexeddb.ts`](../../packages/sdk/src/credential-vault-indexeddb.ts)
- **Boundary:** [ADR-0014](adr/0014-v2-production-vault-and-private-status-refresh.md)
- **Evidence:** [QA](../reports/qa-v2-holder-browser-hardening.md),
  [reliability](../reports/reliability-v2-holder-browser-hardening.md),
  [security](../reports/security-v2-holder-browser-hardening.md) and
  [privacy](../reports/privacy-v2-holder-browser-hardening.md)

## Scope and non-claims

This release-owned PWA uses only synthetic encrypted vaults and public packed-status snapshots. It integrates the
exact content-addressed private-refresh Worker and WASM package in a production-header Chromium build, exercises
the browser persistence/recovery boundary and records sanitized resource evidence. It is not a holder-facing app
and does not admit live production persistence, refresh, proving or presentation.

Both independent admission controls remain false:

- `ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED === false`; and
- the packaged Worker's reviewed policy is forcibly rewritten to `productionApproved: false`.

The Chromium test therefore expects the real module Worker to return only `PROFILE_REJECTED`. The transferred PRF
buffer must still detach and the disposable Worker must terminate. The separate public probe loads the same pinned
WASM and bindings to measure public snapshot/path behavior without accepting a vault payload.

## Production browser envelope

The harness server applies the following controls to every response:

- `default-src 'none'`, same-origin scripts/workers/connects/styles/images/manifest only, no frames, forms, objects,
  fonts or base URL, and `script-src 'wasm-unsafe-eval'` only for the reviewed WebAssembly module;
- `require-trusted-types-for 'script'` with one `ubi2-holder-harness` policy whose script-URL allowlist contains only
  the two reviewed service workers, the exact private-refresh Worker URL and the generated public-probe Worker;
- COOP/COEP/CORP same-origin isolation, `no-referrer`, `nosniff` and a deny-by-default permissions policy; and
- immutable caching only for built public assets, the Worker and exact SHA-256-addressed WASM. `/private/*`, HTML,
  vault backup traffic and every non-GET request are `no-store` and are never placed in Cache Storage.

The production Worker basename remains:

```text
holder-private-status-refresh-worker.ae57f9b95b7f53fc20bf77c3a77b103a37815b65232fff408e0458dd10ad008d.js
```

Its WASM request is forced to the same-origin immutable path ending in
`42123b2ab76133356e55e1ce15461a9dd662f96968f4eee862c668fd7f011cee.wasm`. The Worker independently checks the
326,583-byte length and SHA-256 before compilation. An adversarial controlling service worker that substitutes four
bytes is rejected before a circuit call. Once the package is loaded, ordinary Worker fetch/socket/import
capabilities are irreversibly masked before any private decrypt path could run.

## Whole-vault IndexedDB CAS

`IndexedDbCredentialVaultStore` is bound at construction to one random `vaultId` and exact `{schema,rpId}`. Its
single object-store record contains only:

```text
{ schema, key: "current", revision, vault: <complete encrypted PortableCredentialVault> }
```

It never persists or broadcasts the whole-vault SHA-256. CAS reads and hashes the strict whole vault, then opens one
strict-durability read/write transaction. IndexedDB serializes competing writers; the transaction re-reads the
record and replaces it only if the observed revision is unchanged. Every successful write increments the revision
and commits the entire replacement record. A crash/abort before commit leaves the byte-equivalent old vault; after
commit readers see the complete new vault. No partial payload/key-slot mixture is representable.

Cross-tab `BroadcastChannel` notifications contain one constant schema string only. They are invalidation hints,
not authorization or receipts. Tabs always re-read IndexedDB and use CAS. The Chromium race starts two tabs from
the same digest and requires exactly one winner while preserving all key slots.

## Backup and restore

An exported backup adds an independent AES-256-GCM envelope over the already encrypted complete vault. A caller-
held 256-bit recovery secret is expanded with HKDF-SHA-256 and a fresh 256-bit salt; encryption uses a fresh 96-bit
IV and fixed version/cipher/KDF AAD. Secrets and plaintext byte copies are cleared after use.

Restore authenticates and strictly parses the complete vault before checking the store binding. It can either:

- write only to an empty database; or
- replace an occupied database only through an explicit current whole-vault CAS digest.

Wrong keys, ciphertext changes and wrong vault bindings fail closed. Empty-only restore cannot overwrite a newer
local vault. A restored status witness is never authoritative: the next normal refresh must still resolve the
current finalized public status set under ADR-0014.

## Adversarial and resource evidence

The committed Chromium suite verifies:

- Trusted Types blocks an untrusted HTML string sink and the CSP leaves no third-party script origin;
- a controlling service worker cannot substitute the pinned WASM;
- Cache Storage, DOM, request URLs and request bodies contain no decrypted payload or holder selector;
- the decrypted Worker has no ordinary network capability;
- a simulated preloaded extension/first-party hook can clone the request before native transfer, confirming the
  documented residual threat and the need to keep production admission closed;
- competing tabs produce exactly one CAS winner and content-free invalidation;
- injected transaction failure plus close/reopen exposes only the old whole vault;
- authenticated backup restore succeeds into an empty database while wrong-key, tamper and occupied-store cases
  reject; and
- a 390×844, 3× DPR, 4× CPU-throttled Chromium profile runs 10 fresh public WASM Workers and 20 hard-cancellation
  samples. This is measured emulation evidence, not a physical-device production claim.

The committed local baseline measured 1,179,648 bytes of WASM linear memory for every sample and 0.945 ms
cancellation p95.
CI writes the full sanitized measurements to `holder-browser-hardening-evidence.json` and uploads them as a build
artifact. The committed baseline is
[`holder-browser-hardening-evidence-v1.json`](../../fixtures/v2-production-crypto/holder-browser-hardening-evidence-v1.json).

## Validation

```bash
pnpm test:v2-holder-browser
pnpm test:v2-vault-contract
pnpm test:v2-holder-refresh
pnpm test:v2-holder-refresh-wasm
pnpm --filter @ubi2/sdk typecheck
```

The `v2-vault-contract` workflow runs the Chromium job when any harness, holder SDK, content-addressed artifact,
root script or lockfile input changes. Production admission still requires independent cryptographic/browser and
source-to-WASM audits, physical representative-device evidence, holder-facing WebAuthn UX and an adversarial
testnet soak.
