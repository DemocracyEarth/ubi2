# Browser & Mobile Light Node

**Branch:** `feat/zkpoh-lightnode-design`
**Status:** defined (docs-only; parallel track — does not block or depend on M5–M7 main sequence)
**Owned by:** product-strategist (this doc) → architect (spec) → orchestrator (decompose)
**Parallel track note:** This milestone runs in parallel with the ZK-Passport PoH track. It shares
design surface with ZK-PoH at Stage 3 (on-device NFC passport reading). Neither track blocks the
other; the ZK-PoH team owns `docs/roadmap.md` for their sequencing edits.

---

## Why this milestone exists

The UBI network's promise is universal inclusion: every verified human receives a basic income. That
promise is hollow if participating in the network — even as a reader — requires a Rust toolchain, a
laptop, and a broadband connection. The majority of the humans this network is designed to serve are
phone-first and laptop-never.

Three leverage points make this the right time to define the milestone:

**1. Distribution and inclusion are the network's hardest cold-start problem.**
A UBI chain needs verified humans to have value. Verified humans need a frictionless path to join,
read their balance, and sign transactions. If that path requires installing a binary, the network
self-selects for a small technical minority — the opposite of the whitepaper's intent. A browser tab
or a PWA that opens in one tap on any phone closes the distribution gap by an order of magnitude.

**2. The phone is where most people already hold their identity.**
Governments issue e-passports readable by phone NFC. The phone is the natural locus for a future
ZK-Passport proof-of-humanity flow: the user taps their passport to their phone, the proof is
generated on-device, and is submitted from the same light node. No desktop required. This synergy
with ZK-PoH (see §Synergy points) means the browser/mobile light node is an enabling prerequisite
for the most privacy-preserving PoH path, not merely a convenience.

**3. Running a node should be one tap, not a Rust toolchain.**
The whitepaper calls for a network of verified-human nodes. Today spinning up a node requires Rust,
cargo, and a command line. A WASM-compiled light node that runs inside a browser tab or a mobile
WebView democratizes who runs the network. Each new browser/mobile participant strengthens the
network's geographic and demographic decentralization without requiring them to understand Rust or
operate a server.

---

## Parallel track framing

This milestone does not sit on the M5 → M6 → M7 critical path. It is a parallel investment track:

- **It does not block M5–M7.** The main-sequence milestones can ship independently.
- **It is unblocked by M5 Stage A.** Once there is a real P2P network with a defined sync protocol
  (`ubi2/sync/1`) and gossip topics, a light node has something real to connect to. Stage 1 of this
  track should therefore begin no earlier than M5 Stage A being in progress, and should target
  completion roughly in parallel with M5 Stage B/C.
- **It synergizes with the ZK-Passport PoH track at Stage 3.** The ZK-PoH team owns their roadmap
  entry; this doc records the integration point rather than specifying it.

---

## User-facing goal

A person anywhere in the world opens a browser tab (or installs a PWA, or opens a mobile app) on
their phone. Without installing any native software they can:

- See the live streaming UBI balance of any verified human, updating in real time.
- See their own balance climbing.
- Sign and submit transactions (transfers, vouches, contract invocations) directly from the device,
  without routing through a trusted server.
- Verify that the chain state they are reading is honest, by checking block headers and state roots
  against a set of peers.

Later: tap their e-passport to their phone and generate an on-device ZK proof of identity, submitted
through the same light node to the HumanityHub, with no PII leaving the device.

---

## Why the runtime is already WASM-ready

A build-level invariant already enforced in the codebase: `crates/runtime` is deterministic and
dependency-free — no libp2p, no tokio, no reqwest, no floats, no wall-clock in the consensus path.
This means it already compiles to WASM. The light node does not need to re-implement the state
transition; it imports the runtime WASM module and re-executes block transitions locally to verify
the state root. This is the same re-execution path that M5 followers use; the light node is a
follower that runs in a browser instead of a server.

---

## Exit criteria (user-facing, testable)

### Stage 1 — Browser light node: sync, verify, read, sign

A user visits a URL in any modern browser (Chrome, Firefox, Safari, mobile Safari, Chrome for
Android). No install, no extension, no native binary.

**LC-1 — Sync from peers.**
The browser tab connects to at least one `ubi2-node` peer via a WebSocket or WebTransport bridge
and syncs block headers from genesis to the current tip without any server-side proxy holding
private keys or performing validation on behalf of the user.

**LC-2 — State root verification.**
After syncing, the browser light node recomputes the state root for the latest finalized block
using the WASM-compiled `crates/runtime` and asserts byte-for-byte agreement with the header's
`state_root`. A tampered block causes the light node to display a verification failure, not a
silently wrong balance.

**LC-3 — Live streaming balance visible.**
A verified human's address shows a balance that increments in real time (the streaming UBI drip),
identical to what `eth_getBalance` returns on a full node at the same block height.

**LC-4 — Transaction signing and submission.**
The user signs a transaction (transfer, vouch, or contract invocation) with a key held in-browser
(MetaMask via the EIP-1193 provider interface, or a locally generated key). The signed transaction
is submitted to the network via the peer connection and is gossiped, mined, and confirmed — the
balance updates accordingly. No private key ever leaves the browser.

**LC-5 — No trusted intermediary for reads.**
The balance and block data shown to the user are derived from headers and state the light node
verified itself, not from a server's assertion. An adversarial server that lies about the state
root causes a visible verification error.

### Stage 2 — Progressive Web App (PWA)

**LC-6 — Installable PWA.**
The light node UI is installable as a PWA on Android and iOS (Add to Home Screen). Once installed,
it opens without a browser bar and looks and feels like a native app. The icon appears on the home
screen next to other apps.

**LC-7 — Offline-capable balance read.**
After the PWA has synced once, a user who goes offline can still see their last-verified balance
(cached), with a clear indicator that it is not live. On reconnection the light node re-syncs and
updates.

**LC-8 — Push notification for balance events.**
When the user's balance crosses a round-number threshold (e.g., 100 UBI) or a stream they are
receiving is modified, the PWA delivers a push notification — without a centralized server knowing
the user's identity. The notification payload contains no PII.

### Stage 3 — Mobile wrapper + on-device NFC passport verification

**LC-9 — Native mobile wrapper.**
A thin React Native or Capacitor wrapper packages the Stage 1/2 WASM light node and PWA as a
native iOS and Android application distributed through the App Store and Google Play. The
networking, verification, and signing logic is identical to Stage 1 (no separate mobile codebase
for the consensus path).

**LC-10 — On-device NFC passport read.**
On a supported device (NFC-capable Android; iPhone 7 or later with Core NFC), the user taps their
ICAO-9303 e-passport to the phone. The app reads the MRTD data groups over NFC without transmitting
the raw passport data to any server.

**LC-11 — On-device ZK proof generation.**
The app computes a ZK proof of passport validity (age, nationality, or a predicate thereof) entirely
on-device, using the circuit agreed with the ZK-Passport PoH track. No biometric images, no raw MRZ
data, and no PII leave the device. The proof is a succinct commitment the on-chain HumanityHub can
verify.

**LC-12 — ZK proof submission via light node.**
The on-device ZK proof is submitted as a `requestVerification` call to the HumanityHub through the
device's own light node. The user never needs a desktop. The AI jury quorum evaluates the proof
(or, if the ZK-PoH track replaces the AI jury for passport-backed claims, the on-chain verifier
accepts the proof directly — to be agreed with the ZK-PoH team). On success the user transitions
to `Verified` and streaming UBI begins on their device.

### Stage 4 — Optional block-producing / AI-juror node

**LC-13 — Block production from a mobile/browser node (opt-in).**
A user who explicitly opts in can promote their light node to a block-producing validator. The node
participates in the PoA round-robin proposer schedule. Because the validator must be a `Verified`
human (M5 PoH-gated validator set), this gate is satisfied automatically by Stage 3's NFC flow.
Block production is disabled by default and requires the user to stake (M6 mechanics) and accept
the battery/data cost.

**LC-14 — AI juror role from a mobile node (opt-in).**
A user with a local AI backend available (on-device model or a user-configured remote endpoint) can
run the juror daemon inside the mobile app. The node watches for open `Case`/`ExecCase` entries
assigned to its validator address and submits signed verdicts/effects. This closes the loop: a
phone-first human can participate in the AI-quorum that decides who else is human.

---

## Staged plan

### Stage 1 — Sync + verify + read + sign (browser, no install)

**Goal:** prove the WASM runtime runs in a browser, can sync a real chain, and can verify what it
reads. This is the riskiest assumption (does the runtime actually compile to WASM and run at
acceptable speed in a browser?); retiring it early is the priority.

**Primary outputs:**
- A WASM build target for `crates/runtime` (verify the no-float, no-async constraint already
  satisfied; add a `wasm32-unknown-unknown` CI build check).
- A browser-side sync client (TypeScript, using the existing `packages/sdk`) that connects to a
  full node's WebSocket RPC, downloads block headers, and calls the WASM runtime to re-execute and
  verify the state root.
- A minimal read-only UI: address → streaming balance, chain tip, peer count, verification status
  (green checkmark = state root matches; red = mismatch).
- EIP-1193 signer integration: MetaMask (or any injected provider) signs txs; the light node
  submits them through the peer connection.
- CI: a Playwright test that opens the browser light node pointed at a local devnet, asserts LC-1
  through LC-5.

**Dependencies:** M5 Stage A (a real P2P network with `ubi2/sync/1` and WebSocket RPC). The light
node connects via the existing `eth_subscribe` WebSocket already in `crates/rpc`.

**Out of scope for Stage 1:** offline support, push notifications, native wrapping, NFC, WASM peering
directly (all traffic goes through a WebSocket bridge to a full node — the light node verifies but
does not itself participate in gossip yet).

### Stage 2 — Progressive Web App (PWA)

**Goal:** make the Stage 1 browser experience installable and offline-capable on any phone, closing
the gap between "website" and "app" without App Store friction.

**Primary outputs:**
- A PWA manifest, service worker, and icon set.
- Offline-capable balance cache (IndexedDB-backed block header store so the last verified state
  is readable without a network).
- Web Push notification integration (no PII in payload; user opts in; a self-hostable push relay
  is the first implementation — centralized only as a convenience, never required).
- UX polish: home screen icon, splash screen, install prompt, connection status indicator.

**Dependencies:** Stage 1 complete.

### Stage 3 — Mobile wrapper + NFC passport verification

**Goal:** deliver a native app and the on-device passport flow. This stage's NFC and ZK components
are co-designed with the ZK-Passport PoH track — the circuit and the on-chain verifier interface
are agreed jointly. The light node team owns the mobile scaffolding and the NFC read; the ZK-PoH
team owns the circuit and the on-chain HumanityHub extension.

**Primary outputs:**
- React Native (or Capacitor) wrapper that embeds the Stage 1/2 WASM module; no duplication of
  consensus logic.
- NFC passport read: ICAO-9303 BAC/PACE protocol, MRTD data group extraction, on-device only.
- On-device ZK proof generation: the circuit agreed with ZK-PoH track, compiled to WASM or native.
- `requestVerification` submission via the device's own light node.
- App Store and Google Play distribution.
- E2E demo: a tester taps a test e-passport, the app generates a proof, submits it, and the
  account transitions to `Verified` and begins streaming UBI — entirely on the phone, no desktop
  involved.

**Dependencies:** Stage 2 complete; ZK-Passport PoH track has landed the circuit and on-chain
verifier extension (coordinated handoff).

**ZK-PoH integration point:** The ZK-Passport PoH track defines the proof schema and the
HumanityHub extension for ZK-backed verification. This Stage 3 mobile flow is the primary delivery
vehicle for that proof — the phone NFC reads the passport, the ZK circuit (from ZK-PoH) generates
the proof, and this light node submits it. Neither track gates the other, but Stage 3 is the moment
they converge.

### Stage 4 — Optional producing / AI-juror node (opt-in upgrade)

**Goal:** a phone-first human can optionally become a block producer and AI juror, completing the
vision of a network where any verified human can run any role.

**Primary outputs:**
- Block production flag in the mobile app (disabled by default; requires M6 staking).
- Juror daemon integrated into the mobile wrapper: watches assigned cases, calls a configured AI
  backend (on-device or user-configured remote), submits signed verdicts.
- Battery and data usage disclosure; graceful degradation when the device is off or backgrounded.
- Updated `ubi_getPeers` and `ubi_consensusStatus` visible in the light node UI so a user can see
  their node's contribution to the network.

**Dependencies:** Stage 3 complete; M6 Economics & Governance (staking mechanics for validators).

---

## Synergy points with ZK-Passport PoH

The browser and mobile light node track and the ZK-Passport PoH track converge in ways that make
each stronger:

**1. The phone NFC reads the passport; the light node submits the proof.**
ZK-Passport PoH needs a delivery vehicle: something that can read an NFC chip, run the ZK circuit,
and submit the resulting proof without trusting a server. The Stage 3 mobile wrapper is exactly
that. The ZK-PoH team designs the circuit; the mobile light node is the surface through which every
user exercises it.

**2. On-device proof generation requires on-device compute — the WASM runtime is the precedent.**
The ZK circuit (Groth16, PLONK, or similar) can be compiled to WASM or native and run on-device
for the same reason the `crates/runtime` can: bounded, integer, dependency-free computation.
Proving that the UBI runtime runs acceptably in WASM (Stage 1) de-risks the assumption that ZK
proof generation will also run acceptably on a phone.

**3. Privacy alignment.**
Both tracks share invariant I6 (no PII off-device). The NFC read stays on-device; only the
succinct ZK commitment leaves the phone. This is the whitepaper's "privacy-preserving checks rather
than stored identity" made concrete at the hardware level.

**4. Inclusion alignment.**
A ZK-passport flow that requires a desktop defeats the inclusion argument. A phone-first flow
that reads the passport and generates the proof without leaving the phone is the only version that
reaches the populations for whom UBI is most urgent. Stage 3 of this track is the necessary
infrastructure.

**5. Validator set quality.**
Stage 4 allows a phone-first human (who entered via NFC passport verification) to become a
validator and juror. This extends the PoH-gated validator set beyond laptop-owning developers to
anyone with an e-passport-capable phone, broadening the network's geographic and demographic base.

---

## What this milestone does NOT include

- Full P2P gossip participation from the browser (Stage 1 verifies via a WebSocket bridge; direct
  WASM-based libp2p peering is a later optimization and a backlog item).
- A bespoke mobile wallet UI (the Stage 3 wrapper hosts the existing `apps/wallet` Next.js app;
  a native-design mobile UI is a UX polishing task beyond this milestone's scope).
- Cross-chain bridge or interoperability.
- BFT consensus from a mobile node (Stage 4 is PoA round-robin, consistent with M5's CFT scope).
- Any ZK circuit design or on-chain HumanityHub extension (those are owned by the ZK-Passport PoH
  track; this milestone is a consumer and delivery vehicle, not a designer, of that work).
- Economic parameters, demurrage, fee recycling, governance (M6 main sequence).

---

## Risks and mitigations

**Risk 1 — WASM runtime performance in a browser.**
The block-execution path in `crates/runtime` has never been benchmarked in a browser. On a 10-year-old
phone, re-executing a block with many streaming operations may be slow.
Mitigation: Stage 1's first task is a WASM benchmark on representative hardware. If full
re-execution is too slow, the light node falls back to header-only sync (verify the chain of headers
by checking the `proposer_sig` and `parent_hash` chain, trusting the `state_root` in the header
rather than re-executing the full block). Header-only mode is weaker than full verification but
still much stronger than a trusted server read. Full re-execution remains the target for Stage 1
on desktop; mobile may ship with header-only initially and upgrade as on-device performance improves.

**Risk 2 — WebSocket bridge is a partial trust assumption.**
In Stage 1, the light node connects via WebSocket to a full node. That full node could lie about
the peer count or serve a fake state root. The WASM re-execution mitigates the state-root lie (the
light node catches it); the peer count and block availability are taken on trust. Connecting to
multiple independent full nodes and checking agreement among them reduces this risk; full browser-side
gossip participation is the long-term mitigation and is tracked in the backlog.

**Risk 3 — NFC on iOS is restricted.**
Apple's Core NFC API supports NDEF and ISO 7816 (APDU commands for passport reads) since iOS 13,
but the API has changed across iOS versions and passport reads (extended length APDUs) have a
history of bugs in older iOS releases.
Mitigation: Stage 3 targets iOS 16+ as the minimum for NFC passport reads. Stage 3 acceptance
criteria include a test on physical devices (not simulators), with a specific list of tested
device/iOS version combinations. The NFC read failure path shows a clear "your device does not
support passport reading; use social vouching instead" fallback.

**Risk 4 — App Store policy for crypto/blockchain apps.**
Both Apple and Google have policies that affect crypto wallet and blockchain apps. Distribution
delays or restrictions are a real risk.
Mitigation: Stage 3 targets Progressive Web App (Stage 2) as the primary distribution mechanism;
the native wrapper is additive. Users on platforms with restrictive app stores can use the PWA
installed to their home screen. The native wrapper is submitted with a focus on the identity and UBI
income aspects, not speculation or trading.

**Risk 5 — ZK-PoH circuit availability.**
Stage 3 depends on the ZK-Passport PoH track delivering a circuit and on-chain verifier interface.
If that track slips, Stage 3's NFC flow cannot complete.
Mitigation: Stage 3 ships the NFC read and mobile wrapper independently of the ZK circuit. LC-10
(NFC read) and LC-11 (ZK proof generation) are separable: LC-10 can be demonstrated with a
placeholder proof; LC-11 is conditional on the ZK-PoH circuit landing. LC-12 (submission via
HumanityHub) is the integration milestone and is explicitly joint with ZK-PoH.

---

## Handoff to architect

The architect should produce:

1. A `docs/specs/06-light-node.md` covering the WASM build target for `crates/runtime`, the
   browser sync protocol (WebSocket bridge spec, header vs. full-block re-execution modes), the
   state root verification algorithm in the browser, and the EIP-1193 signing interface.
2. A decision (ADR or note in the spec) on whether to use existing `packages/sdk` directly in the
   browser light node or to create a `packages/light-client` package. The SDK already speaks
   EVM JSON-RPC and `ubi_*`; the question is whether WASM re-execution lives in the SDK or a
   separate package.
3. Guidance on the WebSocket bridge topology: does the light node connect to one full node (simple,
   partial trust) or multiple (better trust, more complexity)? Recommendation: start with one for
   Stage 1, multi-peer for Stage 2.
4. An interface contract with the ZK-Passport PoH team covering the proof schema, the NFC data
   groups required, and the HumanityHub extension API — needed before Stage 3 begins.
5. Stage 1 acceptance criteria operationalized as Playwright tests (LC-1 through LC-5).
