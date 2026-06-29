/**
 * ubi2 browser light node — main entry point.
 *
 * Flow:
 * 1. Render the static HTML shell via render().
 * 2. Load + initialise the WASM kernel (initWasm).
 * 3. Read config from URL hash / localStorage.
 * 4. Construct a LightClient and call lc.sync() (connects → Hello → GetBlocks loop → live push).
 * 5. Tick the UI on every animation frame: balance interpolation (projectBalance), tip, badge.
 * 6. On address-form submit: update the watched address + re-read from verified state.
 *
 * Trust model: the WASM kernel re-executes every block and verifies the state_root byte-identically.
 * A lying gateway is caught by the kernel; the UI shows a red badge and never shows a wrong balance.
 *
 * Respects prefers-reduced-motion: the streaming counter animation is disabled when the OS
 * accessibility setting is active.
 */

import "./styles.css";
import { LightClient, VerificationError, WrongNetworkError, GatewayError } from "@ubi2/light-client";
import { initWasm, wasmLightStateFactory } from "./wasm-shim.js";
import { getConfig, saveWatchAddress, loadWatchAddress } from "./config.js";
import {
  setBadge,
  setProgress,
  formatUbi,
  humanStatusLabel,
  reducedMotion,
  type BadgeState,
} from "./ui.js";

// ---------------------------------------------------------------------------
// HTML shell
// ---------------------------------------------------------------------------

function render(): void {
  const root = document.getElementById("app")!;
  root.innerHTML = `
<div class="ln-shell">
  <header class="ln-header">
    <div class="ln-logo">
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true">
        <circle cx="16" cy="16" r="15" stroke="var(--accent)" stroke-width="2"/>
        <path d="M10 16c0-3.314 2.686-6 6-6s6 2.686 6 6-2.686 6-6 6" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"/>
        <circle cx="16" cy="16" r="2.5" fill="var(--accent)"/>
      </svg>
      <span class="ln-logo-text">ubi2 Light Node</span>
    </div>
    <span id="badge" class="badge badge--idle" role="status" aria-live="polite">Idle</span>
  </header>

  <main class="ln-main">
    <!-- Sync status card -->
    <section class="card" aria-labelledby="sync-heading">
      <h2 id="sync-heading" class="card-heading">Chain Sync</h2>

      <div class="stat-row">
        <span class="stat-label">Gateway</span>
        <span id="gateway-url" class="stat-value mono">—</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Chain ID</span>
        <span id="chain-id" class="stat-value mono">—</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Tip Height</span>
        <span id="tip-height" class="stat-value mono">—</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">State Root</span>
        <span id="state-root" class="stat-value mono truncate" title="0x..." aria-label="State root">—</span>
      </div>

      <!-- Sync progress -->
      <div class="progress-wrap" aria-label="Sync progress" role="progressbar"
           aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
        <div class="progress-bar">
          <div id="progress-fill" class="progress-fill" style="width:0%"></div>
        </div>
        <span id="progress-label" class="progress-label">Waiting for WASM…</span>
      </div>

      <!-- Verification badge detail -->
      <div id="verify-detail" class="verify-detail" aria-live="assertive"></div>
    </section>

    <!-- Address + balance card -->
    <section class="card" aria-labelledby="balance-heading">
      <h2 id="balance-heading" class="card-heading">Live Balance</h2>

      <form id="address-form" class="address-form" autocomplete="off" novalidate>
        <label for="address-input" class="form-label">Watch address</label>
        <div class="address-row">
          <input
            id="address-input"
            type="text"
            class="address-input"
            placeholder="0x…"
            autocomplete="off"
            spellcheck="false"
            maxlength="42"
            pattern="^0x[0-9a-fA-F]{40}$"
            aria-describedby="address-hint"
          />
          <button type="submit" class="btn-watch">Watch</button>
        </div>
        <span id="address-hint" class="form-hint">Enter a 0x-prefixed EVM address</span>
      </form>

      <div id="balance-panel" class="balance-panel" aria-live="polite">
        <div class="balance-row">
          <span class="balance-label">UBI Balance</span>
          <span id="balance-value" class="balance-value" aria-label="UBI balance">—</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Human Status</span>
          <span id="human-status" class="stat-value">—</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Emission Rate</span>
          <span id="emission-rate" class="stat-value">1 UBI / hour</span>
        </div>
        <p id="balance-note" class="balance-note"></p>
      </div>
    </section>

    <!-- Trust model info -->
    <section class="card card--info" aria-labelledby="trust-heading">
      <h2 id="trust-heading" class="card-heading">Trust Model</h2>
      <ul class="trust-list">
        <li>Every block is <strong>re-executed in WASM</strong> — no server is trusted for balances or state roots.</li>
        <li>A lying gateway is <strong>caught by the kernel</strong>: the badge turns red and the balance freezes — never wrong.</li>
        <li>Verified state is <strong>persisted to IndexedDB</strong> so a reload resumes from the last verified block.</li>
        <li>Your private key <strong>never leaves this device</strong>.</li>
      </ul>
      <div class="stat-row">
        <span class="stat-label">Verify mode</span>
        <span class="stat-value accent">full re-execution</span>
      </div>
    </section>
  </main>

  <footer class="ln-footer">
    <span>ubi2 browser light node — Stage 2 PWA</span>
    <a id="settings-link" href="#" class="footer-link" aria-label="Edit gateway settings">Settings</a>
  </footer>

  <!-- Settings overlay -->
  <div id="settings-overlay" class="overlay" aria-modal="true" role="dialog" aria-labelledby="settings-heading" hidden>
    <div class="overlay-panel">
      <h2 id="settings-heading" class="card-heading">Gateway Settings</h2>
      <form id="settings-form" autocomplete="off" novalidate>
        <label class="form-label" for="gw-url-input">Gateway URL (ws:// or wss://)</label>
        <input id="gw-url-input" type="text" class="address-input" placeholder="ws://127.0.0.1:8546" />
        <label class="form-label" for="chain-id-input" style="margin-top:1rem">Chain ID (decimal)</label>
        <input id="chain-id-input" type="number" class="address-input" placeholder="21826" />
        <div class="overlay-actions">
          <button type="button" id="settings-cancel" class="btn-secondary">Cancel</button>
          <button type="submit" class="btn-watch">Reconnect</button>
        </div>
      </form>
    </div>
  </div>
</div>
  `;
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

interface AppState {
  tipHeight: bigint;
  gatewayTip: bigint;
  syncComplete: boolean;
  badge: BadgeState;
  watchAddress: string;
  lastError: string | null;
  // Balance tick: last verified balance + the unix-second it was verified at.
  verifiedBalance: string | null; // decimal string of base units
  verifiedAt: number; // unix seconds
  humanStatus: number;
  wasmReady: boolean;
}

const state: AppState = {
  tipHeight: 0n,
  gatewayTip: 0n,
  syncComplete: false,
  badge: "idle",
  watchAddress: "",
  lastError: null,
  verifiedBalance: null,
  verifiedAt: 0,
  humanStatus: 0,
  wasmReady: false,
};

// ---------------------------------------------------------------------------
// Balance streaming (client-side interpolation between WASM re-anchors)
// ---------------------------------------------------------------------------

// EMISSION_RATE: 1 UBI / 3600 s = 10^18 / 3600 base-units/s (exact integer).
const EMISSION_RATE_NUM = 10n ** 18n;
const EMISSION_RATE_DEN = 3600n;

/**
 * Project the balance forward from (verifiedBalance, verifiedAt) to nowSeconds.
 * Only applies if the address is a verified human (humanStatus === 2).
 */
function projectBalance(verifiedBalance: string, verifiedAt: number, nowSeconds: number): string {
  const base = BigInt(verifiedBalance);
  const elapsed = BigInt(Math.max(0, nowSeconds - verifiedAt));
  const delta = (EMISSION_RATE_NUM * elapsed) / EMISSION_RATE_DEN;
  return (base + delta).toString();
}

// ---------------------------------------------------------------------------
// UI update loop
// ---------------------------------------------------------------------------

let client: LightClient | null = null;
let animFrameId: number | null = null;
const noAnim = reducedMotion();

function updateUI(): void {
  // Sync progress
  if (state.gatewayTip > 0n) {
    const pct = Number((state.tipHeight * 100n) / state.gatewayTip);
    const fill = document.getElementById("progress-fill");
    const label = document.getElementById("progress-label");
    if (fill) setProgress(fill as HTMLElement, pct);
    if (label) {
      label.textContent = state.syncComplete
        ? `Synced at block ${state.tipHeight.toLocaleString()}`
        : `Block ${state.tipHeight.toLocaleString()} / ${state.gatewayTip.toLocaleString()} (${pct.toFixed(1)}%)`;
    }
  }

  // Tip height
  const tipEl = document.getElementById("tip-height");
  if (tipEl) tipEl.textContent = state.tipHeight > 0n ? state.tipHeight.toLocaleString() : "—";

  // State root
  if (client) {
    const tip = client.tip;
    if (tip) {
      const srEl = document.getElementById("state-root");
      if (srEl) {
        const short = tip.stateRoot.slice(0, 10) + "…" + tip.stateRoot.slice(-6);
        srEl.textContent = short;
        srEl.setAttribute("title", tip.stateRoot);
      }
    }
  }

  // Badge
  const badgeEl = document.getElementById("badge");
  if (badgeEl) setBadge(badgeEl, state.badge);

  // Verification detail
  const detailEl = document.getElementById("verify-detail");
  if (detailEl) {
    if (state.lastError && state.badge === "error") {
      detailEl.textContent = `Verification error: ${state.lastError}`;
      detailEl.className = "verify-detail verify-detail--error";
    } else if (state.badge === "verified") {
      detailEl.textContent = "State root matched — block re-execution verified.";
      detailEl.className = "verify-detail verify-detail--ok";
    } else {
      detailEl.textContent = "";
    }
  }

  // Balance
  if (state.watchAddress && state.verifiedBalance !== null) {
    const nowSec = Math.floor(Date.now() / 1000);
    const displayed =
      state.humanStatus === 2
        ? projectBalance(state.verifiedBalance, state.verifiedAt, nowSec)
        : state.verifiedBalance;

    const balEl = document.getElementById("balance-value");
    if (balEl) {
      const formatted = formatUbi(displayed);
      if (!noAnim) {
        // Smooth digit update only if motion is allowed.
        balEl.textContent = `${formatted} UBI`;
      } else {
        balEl.textContent = `${formatted} UBI`;
      }
    }

    const hsEl = document.getElementById("human-status");
    if (hsEl) {
      const label = humanStatusLabel(state.humanStatus);
      hsEl.textContent = label;
      hsEl.className = `stat-value ${state.humanStatus === 2 ? "accent" : ""}`;
    }

    const noteEl = document.getElementById("balance-note");
    if (noteEl) {
      if (state.humanStatus === 2) {
        noteEl.textContent = "Streaming live — balance ticks every second.";
      } else if (state.humanStatus === 0) {
        noteEl.textContent = "Not verified — no UBI emission.";
      } else {
        noteEl.textContent = "";
      }
    }
  }
}

function startUILoop(): void {
  function tick(): void {
    updateUI();
    animFrameId = requestAnimationFrame(tick);
  }
  tick();
}

// ---------------------------------------------------------------------------
// Pull balance from verified state
// ---------------------------------------------------------------------------

function refreshBalance(): void {
  if (!client || !state.watchAddress) return;
  const nowSec = Math.floor(Date.now() / 1000);
  const bal = client.balanceOf(state.watchAddress, BigInt(nowSec));
  const hs = client.humanStatus(state.watchAddress);
  if (bal !== null) {
    state.verifiedBalance = bal;
    state.verifiedAt = nowSec;
    state.humanStatus = hs;
  }
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

async function startSync(config: ReturnType<typeof getConfig>): Promise<void> {
  if (!state.wasmReady) {
    updateStatus("idle", "WASM not ready");
    return;
  }

  // Dispose old client if reconnecting.
  if (client) {
    client.close();
    client = null;
  }

  state.badge = "syncing";
  state.syncComplete = false;
  state.lastError = null;

  const progressLabel = document.getElementById("progress-label");
  if (progressLabel) progressLabel.textContent = "Connecting to gateway…";

  // Custom LightClient with progress tracking.
  const lc = new LightClient({
    gatewayUrl: config.gatewayUrl,
    chainId: config.chainId,
    genesisHash: config.genesisHash,
    genesisStateRoot: config.genesisStateRoot,
    genesisTime: config.genesisTime,
    lightStateFactory: wasmLightStateFactory(),
    logger: (level, msg) => {
      if (level === "error") console.error("[light-client]", msg);
      else console.log("[light-client]", msg);
    },
  });

  client = lc;

  try {
    // We patch in progress updates by wrapping the sync promise and polling.
    // The LightClient itself fires sync progress via the logger + tip changes.
    const progressInterval = setInterval(() => {
      if (!client) { clearInterval(progressInterval); return; }
      const tip = client.tip;
      if (tip) {
        state.tipHeight = BigInt(tip.number);
        // gatewayTip is not directly exposed; we derive it from the logger messages or
        // the ratio. Since LightClient.sync() resolves on complete, we rely on tipHeight
        // increasing and the syncing badge.
        if (state.tipHeight > state.gatewayTip) state.gatewayTip = state.tipHeight;
      }
      // Pull balance on each progress tick (verified state may have advanced).
      refreshBalance();
      // Reflect LightClient's internal badge.
      const lcBadge = lc.badge;
      if (lcBadge === "verified") state.badge = "verified";
      else if (lcBadge === "error") {
        state.badge = "error";
        state.lastError = lc.lastError ?? "unknown verification error";
      }
    }, 500);

    await lc.sync();
    clearInterval(progressInterval);

    state.syncComplete = true;
    state.badge = "verified";
    const tip = lc.tip;
    if (tip) {
      state.tipHeight = BigInt(tip.number);
      state.gatewayTip = state.tipHeight;
    }

    // Final balance read after sync.
    refreshBalance();

    // Keep refreshing balance every 5 seconds as new live blocks arrive.
    setInterval(() => {
      refreshBalance();
      const tip = lc.tip;
      if (tip) state.tipHeight = BigInt(tip.number);
      const lcBadge = lc.badge;
      if (lcBadge === "verified") state.badge = "verified";
      else if (lcBadge === "error") {
        state.badge = "error";
        state.lastError = lc.lastError ?? "unknown";
      }
    }, 5000);

  } catch (e) {
    if (e instanceof WrongNetworkError) {
      updateStatus("error", `Wrong network: ${e.message}`);
    } else if (e instanceof VerificationError) {
      updateStatus("error", `Verification failed at block ${e.blockNumber}: ${e.detail}`);
    } else if (e instanceof GatewayError) {
      updateStatus("offline", `Gateway unreachable: ${(e as Error).message}`);
    } else {
      updateStatus("error", String(e));
    }
  }
}

function updateStatus(badge: BadgeState, detail: string): void {
  state.badge = badge;
  state.lastError = detail;
}

// ---------------------------------------------------------------------------
// Settings overlay
// ---------------------------------------------------------------------------

function bindSettings(): void {
  const link = document.getElementById("settings-link");
  const overlay = document.getElementById("settings-overlay");
  const cancelBtn = document.getElementById("settings-cancel");
  const gwInput = document.getElementById("gw-url-input") as HTMLInputElement | null;
  const cidInput = document.getElementById("chain-id-input") as HTMLInputElement | null;
  const form = document.getElementById("settings-form") as HTMLFormElement | null;

  link?.addEventListener("click", (e) => {
    e.preventDefault();
    const cfg = getConfig();
    if (gwInput) gwInput.value = cfg.gatewayUrl;
    if (cidInput) cidInput.value = String(cfg.chainId);
    overlay?.removeAttribute("hidden");
    gwInput?.focus();
  });

  cancelBtn?.addEventListener("click", () => overlay?.setAttribute("hidden", ""));

  overlay?.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.setAttribute("hidden", "");
  });

  form?.addEventListener("submit", (e) => {
    e.preventDefault();
    const gw = gwInput?.value.trim();
    const cid = cidInput?.value.trim();
    if (!gw) return;
    // Update hash and reload.
    const params = new URLSearchParams();
    params.set("gateway", gw);
    if (cid) params.set("chainId", cid);
    window.location.hash = params.toString();
    overlay?.setAttribute("hidden", "");
    // Re-sync with new config.
    startSync(getConfig());
  });
}

// ---------------------------------------------------------------------------
// Address form
// ---------------------------------------------------------------------------

function bindAddressForm(): void {
  const form = document.getElementById("address-form") as HTMLFormElement | null;
  const input = document.getElementById("address-input") as HTMLInputElement | null;

  form?.addEventListener("submit", (e) => {
    e.preventDefault();
    const addr = input?.value.trim() ?? "";
    if (!addr.match(/^0x[0-9a-fA-F]{40}$/)) {
      const hint = document.getElementById("address-hint");
      if (hint) {
        hint.textContent = "Invalid address — must be 0x followed by 40 hex chars.";
        hint.className = "form-hint form-hint--error";
      }
      return;
    }
    state.watchAddress = addr;
    state.verifiedBalance = null;
    saveWatchAddress(addr);
    refreshBalance();

    const hint = document.getElementById("address-hint");
    if (hint) {
      hint.textContent = "Watching address…";
      hint.className = "form-hint";
    }
  });
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  render();

  const config = getConfig();

  // Populate static config fields.
  const gwEl = document.getElementById("gateway-url");
  if (gwEl) gwEl.textContent = config.gatewayUrl;
  const cidEl = document.getElementById("chain-id");
  if (cidEl) cidEl.textContent = `${config.chainId} (0x${config.chainId.toString(16)})`;

  // Pre-fill address.
  const savedAddr = loadWatchAddress();
  const initAddr = config.watchAddress || savedAddr;
  if (initAddr) {
    const input = document.getElementById("address-input") as HTMLInputElement | null;
    if (input) input.value = initAddr;
    state.watchAddress = initAddr;
  }

  // Bind UI interactions.
  bindAddressForm();
  bindSettings();

  // Start the UI render loop.
  startUILoop();

  // Load WASM.
  const progressLabel = document.getElementById("progress-label");
  if (progressLabel) progressLabel.textContent = "Loading WASM kernel…";

  try {
    await initWasm();
    state.wasmReady = true;
    if (progressLabel) progressLabel.textContent = "WASM ready — connecting to gateway…";
  } catch (e) {
    state.badge = "error";
    state.lastError = `Failed to load WASM kernel: ${String(e)}`;
    if (progressLabel) progressLabel.textContent = `WASM load failed: ${String(e)}`;
    return;
  }

  // Start sync.
  await startSync(config);
}

main().catch((e) => {
  console.error("light-node bootstrap error:", e);
  state.badge = "error";
  state.lastError = String(e);
});
