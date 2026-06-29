/**
 * Pure DOM helpers for the light-node UI. No framework dependency — vanilla TS + CSS custom props.
 *
 * Respects prefers-reduced-motion: balance ticker animations are disabled when the media query matches.
 */

export function reducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// ---------------------------------------------------------------------------
// Element helpers
// ---------------------------------------------------------------------------

export function qs<T extends Element>(selector: string, root: ParentNode = document): T {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`qs: "${selector}" not found`);
  return el;
}

export function setText(selector: string, text: string, root: ParentNode = document): void {
  const el = document.querySelector(selector);
  if (el) el.textContent = text;
}

export function setAttr(selector: string, attr: string, value: string, root: ParentNode = document): void {
  const el = document.querySelector(selector);
  if (el) el.setAttribute(attr, value);
}

// ---------------------------------------------------------------------------
// Badge / status helpers
// ---------------------------------------------------------------------------

export type BadgeState = "idle" | "syncing" | "verified" | "error" | "offline";

const BADGE_LABELS: Record<BadgeState, string> = {
  idle: "Idle",
  syncing: "Syncing...",
  verified: "Verified",
  error: "Mismatch",
  offline: "Offline",
};

const BADGE_CLASSES: Record<BadgeState, string> = {
  idle: "badge--idle",
  syncing: "badge--syncing",
  verified: "badge--verified",
  error: "badge--error",
  offline: "badge--offline",
};

export function setBadge(el: Element, state: BadgeState): void {
  for (const cls of Object.values(BADGE_CLASSES)) el.classList.remove(cls);
  el.classList.add(BADGE_CLASSES[state]);
  el.textContent = BADGE_LABELS[state];
  el.setAttribute("aria-label", `Verification status: ${BADGE_LABELS[state]}`);
}

// ---------------------------------------------------------------------------
// Human-status label
// ---------------------------------------------------------------------------

const HUMAN_STATUS_LABELS = [
  "Unverified",
  "Pending",
  "Verified (streaming UBI)",
  "Challenged",
  "Revoked",
];

export function humanStatusLabel(status: number): string {
  return HUMAN_STATUS_LABELS[status] ?? "Unknown";
}

// ---------------------------------------------------------------------------
// Number formatting
// ---------------------------------------------------------------------------

const UBI = 10n ** 18n;
const DECIMALS = 4; // display 4 decimal places

/**
 * Format a base-unit decimal string (e.g. "1234567890000000000000") to human-readable UBI.
 * Uses BigInt arithmetic — no float.
 */
export function formatUbi(baseUnits: string): string {
  const n = BigInt(baseUnits);
  const whole = n / UBI;
  const frac = n % UBI;
  // Pad fraction to 18 digits then take DECIMALS.
  const fracStr = frac.toString().padStart(18, "0").slice(0, DECIMALS);
  return `${whole.toLocaleString()}.${fracStr}`;
}

/**
 * Compute delta between two base-unit strings (positive = increase).
 */
export function ubiBigint(baseUnits: string): bigint {
  return BigInt(baseUnits);
}

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------

export function setProgress(el: HTMLElement, value: number): void {
  // value: 0–100
  el.style.width = `${Math.min(100, Math.max(0, value)).toFixed(1)}%`;
  el.setAttribute("aria-valuenow", String(Math.round(value)));
}
