# V2 holder reference browser/WASM runtime

- **Status:** deterministic synthetic browser proof implemented; permanently non-presentable
- **SDK:**
  [`zk-holder-reference-browser-runtime.ts`](../../packages/sdk/src/zk-holder-reference-browser-runtime.ts)
- **Worker control plane:**
  [`v2-holder-reference-prover-worker.md`](v2-holder-reference-prover-worker.md)
- **Research WASM:** [`tools/v2-crypto-bench`](../../tools/v2-crypto-bench)
- **Cross-lane boundary:** [`ADR-0012`](adr/0012-v2-cross-lane-interface-freeze.md)

## Profile decision

No production cryptographic profile was ratified when this slice began. Merged `main` still states all of the
following:

- ADR-0012: the production cryptographic suite remains unratified;
- the production-profile gate: no production manifest is checked in or approved; and
- the canonical interface fixture: `productionCryptography = unratified`.

The release admission gate validates a future reviewed profile; it does not select cryptography. This runtime
therefore executes only the already-committed deterministic public-toxic-waste research fixture. It does not accept
a profile manifest, live credential, proving key, witness or proof from its caller and cannot activate a verifier.

## Implemented boundary

The browser adapter connects the reference-only Worker protocol to the real Rust/WASM 18-signal research proof:

```text
browser host                         disposable module Worker
------------                         ------------------------
same-origin Worker URL ────────────► generated Rust/WASM bindings
synthetic fixture + 18 signals ────► deterministic in-WASM witness/setup
deadline + memory cap               Groth16 prove + local verify
                         progress ◄─ WASM linear-memory high-water values
abort/deadline ─► terminate()        proof/key/witness memory discarded
                          receipt ◄─ exact 18 signals; no proof bytes
```

The worker-private Rust export constructs the synthetic witness, performs deterministic setup, generates the
research Groth16 proof and verifies it. It then discards the proof and verification key before returning a strict
sanitized WASM report containing only:

- its immutable reference schema and public-toxic-waste warning;
- pinned constraint and witness-variable counts;
- the exact 18 decimal public inputs; and
- `proof_verified: true`.

The TypeScript adapter independently pins those counts and signals, runs the existing canonical signal decoder and
rejects unknown fields, non-canonical decimals, relabeling, false verification or any changed signal. The outer
Worker runtime serializes only its existing `reference-only-unratified`, `presentationReady: false` receipt.

## Browser isolation

`createZkHolderReferenceBrowserClient` accepts one absolute HTTP(S) Worker URL. In a browser it must be same-origin;
credentials, URL fragments, `data:` and `blob:` entries reject. It always launches a named module Worker. Artifact
or proof bytes are not constructor options or Worker message fields.

The generated WASM call is synchronous. JavaScript cancellation cannot interrupt it cooperatively, so the host
continues to enforce cancellation and deadlines with `Worker.terminate()`. Each proof uses a fresh Worker and the
engine drops its generated-binding reference during teardown. WASM memory values are checked before and after the
proof; exceeding the caller's ceiling prevents a receipt.

The runtime reports `loading-artifacts`, `building-witness`, `proving` and `verifying` phases. These are execution
milestones, not a promise that synchronous WASM can yield within its proof call.

## Public versus private

| Data | Location | Result |
|---|---|---|
| synthetic fixture tag and exact 18 signals | host/Worker messages | local public reference data |
| Worker URL, progress, deadline and memory ceiling | browser control plane | ephemeral local metadata |
| synthetic credential/witness | Rust/WASM memory | constructed internally; never messaged |
| deterministic proving and verification keys | Rust/WASM memory | generated internally; discarded |
| research proof | Rust/WASM memory | locally verified; discarded |
| live passport attributes, holder secret, status slot and vault plaintext | nowhere in this slice | not accepted |
| reference receipt | caller memory | non-presentable; contains no proof |

The synthetic fixture carries only repository test values. No real passport data is used.

## Deterministic and adversarial evidence

The SDK suite checks exact signal/count parity, successful teardown, progress, memory accounting and omission of
credential/proof fields. It also rejects substituted signals, false verification, changed schemas, unknown proof
fields, non-canonical decimals, unsupported Worker URLs, memory overrun and sensitive loader errors.

The static smoke fixture builds the actual Rust WASM and bundles the real module Worker:

```bash
tools/v2-crypto-bench/browser/build-holder-reference-smoke.sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory tools/v2-crypto-bench/browser
```

`holder-reference-smoke.html` exercises a complete proof. `?mode=cancel` aborts when the Worker reports the proving
phase and demonstrates hard termination of synchronous WASM. Both pages expose only a small pass/fail JSON result;
the DOM receives no proof, key or witness.

## Unchanged interfaces

- The frozen 18-signal order and values' canonicality rules are unchanged.
- No production credential, commitment, issuer signature, status hash or circuit identifier is selected.
- No Solidity ABI, verifier, registry, event, storage or status-root format changes.
- The Rust circuit relation and committed verifier fixtures are unchanged; this slice adds only a sanitized browser
  export around the existing deterministic research proof.

## NEEDS-INTEGRATION-DECISION

A future production Worker must be a new profile-specific adapter admitted by the release gate. It must not accept
this synthetic fixture id, deterministic setup, research circuit id or reference receipt. Ratification must supply
content-addressed artifacts, a production vault-to-worker input contract, issuer/status witness requirements,
proof encoding, local verification behavior and representative device budgets before live credentials enter this
runtime class.

**Resolved additively after ADR-0013:** the dedicated boundary is now specified in
[`v2-holder-profile-worker-wasm.md`](v2-holder-profile-worker-wasm.md). The old reference protocol remains frozen;
the new adapter fixes the ratified profile, verifies content-addressed artifacts, decrypts vaults only inside the
Worker and returns locally verified proof output. Production credential-envelope and ceremony inputs remain
explicit admission blockers rather than changes to this reference format.
