# QA gate — V2 holder browser hardening

- **Gate:** browser/persistence implementation acceptance
- **Reviewer:** Codex QA review
- **Date:** 2026-08-27
- **Scope:** production-header PWA harness, exact Worker package, IndexedDB CAS and backup/restore drills
- **Verdict:** **PASS — production-disabled evidence only**

No blocking correctness finding remains in this slice.

## Acceptance evidence

- The production build serves the exact reviewed Worker basename and SHA-256-addressed WASM path under CSP,
  Trusted Types and same-origin isolation.
- A real module-Worker request reaches the packaged boundary, detaches the PRF input and returns
  `PROFILE_REJECTED` because both admission controls remain false.
- A public-only disposable probe runs the real depth-24 WASM path and reports pinned WASM/binding identities.
- Two Chromium tabs starting at one whole-vault digest produce exactly one successful IndexedDB commit.
- Crash/abort and close/reopen preserve the old complete vault. Successful writes preserve the complete envelope
  and key-slot set.
- Empty restore reproduces the exact vault; wrong key, tamper and occupied-store restore fail closed.
- The focused suite covers CSP/Trusted Types, PWA control/cache rules, service-worker substitution, extension
  pre-transfer exposure, network selectors, persisted record shape, mobile-profile memory and cancellation.

## Required validation

- `pnpm test:v2-holder-browser` — PASS (4 Chromium tests)
- `pnpm --filter @ubi2/holder-browser-harness typecheck` — PASS
- `pnpm --filter @ubi2/sdk typecheck` — PASS
- existing ADR-0014 contract/Worker/WASM suites — required unchanged gates

**QA approval:** merge the browser hardening and recovery evidence. Do not enable production admission.
