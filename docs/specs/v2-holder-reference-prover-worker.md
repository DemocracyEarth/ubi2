# V2 holder reference prover Worker boundary

- **Status:** reference-only execution control plane implemented; no production proof or credential path
- **SDK:**
  [`zk-holder-reference-prover-worker.ts`](../../packages/sdk/src/zk-holder-reference-prover-worker.ts)
- **Browser/WASM adapter:**
  [`v2-holder-reference-browser-runtime.md`](v2-holder-reference-browser-runtime.md)
- **Private handoff:** [`v2-holder-reference-handoff.md`](v2-holder-reference-handoff.md)
- **Cross-lane boundary:** [`ADR-0012`](adr/0012-v2-cross-lane-interface-freeze.md)

## Why this slice is reference-only

Merged `main` still classifies the credential commitment, issuer authentication, status hash suite, circuit ids,
proving keys and verifiers as unratified. The release lane's production-profile admission gate is gate machinery;
it explicitly approves no profile. Building a live proof path now would therefore choose production cryptography
inside the holder lane and bypass ADR-0012.

This slice implements the largest safe part that does not depend on that choice: the lifecycle and isolation
boundary around a dedicated Worker. A worker-private engine can run and verify a synthetic fixture while the SDK
enforces bounded progress, cancellation, deadlines, memory limits, exact V1 public-signal equality and teardown.
The protocol has no credential witness, proving key, circuit artifact, issuer envelope or proof bytes.

Every receipt is hard-coded:

```text
profileStatus      = reference-only-unratified
presentationReady = false
```

It reports that a worker-private synthetic run verified and was resource-bounded. It is not a ZK presentation and
cannot be submitted to `PredicateVerifier`.

## Boundary and lifecycle

```text
host thread                                      dedicated Worker
-----------                                      ----------------
synthetic fixture id + expected 18 signals  ───► strict one-shot command parser
deadline + maximum WASM memory                   worker-private fixture/engine
                                      progress ◄─ monotonic phase/% + memory
abort or deadline ─► cancel + terminate()        synchronous WASM is hard-stopped
                                      receipt  ◄─ verified=true, no proof bytes
                                                  engine.destroy()
```

`ZkHolderReferenceProverClient` creates one fresh Worker per run and always terminates it after success, failure,
cancellation or deadline. Sending a cooperative cancel message is best effort; `Worker.terminate()` is the hard
security boundary because a synchronous WASM prover cannot process another message while it is computing.

The worker runtime accepts one start only. A second start, malformed/extended object, wrong schema/status, invalid
job id, non-canonical signal vector or out-of-range resource limit fails closed. Job ids are random 128-bit
base64url values used only by the local control plane and never written to a vault, proof, chain, log or analytics.

## Inputs and outputs

The host command contains only:

- a bounded `synthetic:` tag selecting a **synthetic fixture compiled into the worker**;
- the exact serialized frozen 18-signal V1 vector the fixture must reproduce;
- an absolute deadline no more than ten minutes away; and
- a WASM-memory ceiling from 16 MiB through 1 GiB.

`fixtureId` is not a credential id, commitment, transcript hash or subject. The worker-private engine maps it to a
fixture; this protocol provides no field through which a host can send a credential or witness.

The worker may report these monotonic phases: `initializing`, `loading-artifacts`, `building-witness`, `proving`
and `verifying`. Percent cannot decrease, phases cannot move backward, and each update carries current WASM linear
memory. Crossing the caller's cap aborts with the bounded `resource-limit` code.

The terminal receipt contains the fixture id, exact 18 public signals, `proofVerified: true`, peak reported memory
and the immutable reference-only labels. It deliberately omits proof bytes and all benchmark internals. An engine
that returns `verified=false`, changes one public signal, reports a malformed result, exceeds memory or throws for
any reason produces only a bounded failure code. Raw engine/WASM error text is never reflected across the Worker
boundary.

## Public versus private

| Data | Location | Visibility |
|---|---|---|
| fixture id, expected 18 signals, progress and resource ceilings | local host/Worker messages | synthetic/public reference data only |
| proof bytes and proving-key bytes | worker-private engine, if its fixture needs them | never represented or returned by this protocol |
| synthetic witness | compiled/constructed inside the worker-private engine | never crosses the message boundary |
| live credential, passport claims, holder secret, blinding, status slot and transcript | not accepted by this slice | absent |
| job id | ephemeral local control state | never persisted, transmitted or used as an application identifier |
| reference receipt | caller memory | non-presentable execution evidence only |

The encrypted holder vault is not unlocked by this module. WebAuthn UI, IndexedDB, recovery, backup and live
credential persistence remain out of scope.

## Compatibility and unchanged shared interfaces

- The exact 18 public signals remain unchanged and are parsed with the existing SDK decoder.
- No Solidity ABI, event, storage, verifier, circuit id, status-root format or issuer-authentication format changes.
- No production credential or Worker wire format is declared. This SDK-local reference protocol is not a profile
  manifest and must not be adopted by the circuit/verifier lane as production merely because it is versioned.
- Packed status remains the ADR-0012 testnet integration shape. This slice neither selects nor hashes a status tree.

## Adversarial evidence

The SDK test links an in-memory Worker pair to the same host/runtime interfaces used by browsers and proves:

- a synthetic run reproduces the exact 18 signals, emits monotonic progress and tears down both Worker and engine;
- the command, events and receipt contain no credential field, passport claim or proof byte field;
- a sensitive engine error becomes only `proving-failed` and its text never leaves the worker;
- memory overrun, phase rollback, signal substitution, `verified=false`, expired deadline and unknown fields reject;
- host cancellation hard-terminates the Worker, including an engine that never cooperates; and
- a receipt cannot relabel itself as production or presentation-ready.

## NEEDS-INTEGRATION-DECISION

After the circuit/verifier lane publishes a ratified parameter/artifact manifest and the integration lead accepts
it, the holder lane must add a **new profile-specific adapter and receipt/proof path**. It must not mutate or
relabel this reference-only protocol. That integration must decide and test:

1. the content-addressed WASM, proving-key and verification-key inputs allowed in the Worker;
2. how an unlocked production vault enters worker-private memory without exposing plaintext to application state;
3. the exact issuer-authentication and status-witness inputs required by the selected circuit;
4. how proof bytes and the 18 signals are returned and locally verified before EVM submission;
5. representative mobile memory/time ceilings and hard-failure UX; and
6. the unresolved slot/epoch race and any required credential migration/reissuance.

Until those decisions merge, this receipt is the terminal output. No caller may turn it into calldata or treat a
successful synthetic run as evidence that a live credential can prove a predicate.

The follow-on browser adapter now runs the existing deterministic 18-signal research proof in real Rust/WASM and a
real disposable module Worker. Its public-toxic-waste setup, synthetic witness, key and proof stay Worker-private;
only this same non-presentable receipt returns. That proves browser execution/isolation without satisfying or
bypassing any production-profile decision above.
