"use client";

/**
 * Home — landing view for the ubi2 wallet dApp.
 *
 * Shows the project thesis, a live streaming balance, and navigates into every
 * working feature.  Designed to be read on first open; one click to any pillar.
 */

import type { Section } from "./nav";

// ---- Inline PoH mark (fingerprint path, gradient filled) -------------------------
// Minimal path extracted from poh-logo.svg for use as a small icon.
function PohMark({ size = 28 }: { size?: number }) {
  const id = "poh-home-grad";
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 370 434"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={id} x1="89" y1="75" x2="279" y2="358" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFFF00" />
          <stop offset="100%" stopColor="#FF6699" />
        </linearGradient>
      </defs>
      {/* fingerprint-in-shield from poh-logo.svg — the gradient-filled path */}
      <path
        fill={`url(#${id})`}
        d="
M 347.25 181.1
Q 347.25 147.05 334.2 115.65 321.15 84.2 297.1 60.15 273.05 36.05 241.6 23 210.15 10 176.15 9.95
 174.9 9.95 173.65 9.95 172.4 9.95 171.15 9.95
 137.1 10 105.65 23 74.25 36.05 50.2 60.15 26.1 84.2 13.1 115.65 0.05 147.05 0 181.1
 0 182.23 0 183.35 0 184.73 0 186.1
 0.05 203.45 4.5 220.25 8.9 237.1 17.4 252.25 25.9 267.4 37.9 279.95 49.95 292.5 64.75 301.65
L 79.75 310.85 79.75 418.7
Q 79.75 420.75 81.2 422.2 82.7 423.65 84.75 423.65
L 242.6 423.65
Q 244.65 423.65 246.1 422.2 247.6 420.75 247.6 418.7
L 247.6 377.15 295.75 377.15
Q 300.7 377.15 305.3 375.25 309.85 373.35 313.4 369.85 316.9 366.35 318.8 361.75 320.7 357.2 320.7 352.25
L 320.7 304.05 351.1 304.05
Q 355.5 304.05 359.45 302.05 363.4 300 365.95 296.45 368.5 292.85 369.2 288.5
 369.59 285.87 369.2 283.3 369.82 279.02 368.4 274.95
L 347.25 212.2 347.25 181.1
M 332.3 218
Q 332.3 218.85 332.55 219.6
L 353.95 283.1
Q 354 283.19 354 283.25 353.62 284.54 352.85 285.65 351.7 287.25 349.9 288.2 348.29 289.01 346.5 289.05
L 310.7 289.05
Q 308.65 289.1 307.15 290.55 305.75 292 305.7 294.05
L 305.7 347.55
Q 305.64 350.35 304.55 352.95 303.4 355.7 301.35 357.8 299.25 359.9 296.5 361.05 293.89 362.14 291.05 362.2
L 237.6 362.2
Q 235.55 362.2 234.05 363.65 232.6 365.1 232.6 367.2
L 232.6 408.7 94.75 408.7 94.75 303.05
Q 94.75 301.75 94.1 300.65 93.45 299.5 92.35 298.8
L 74.95 288.15
Q 61.25 279.65 50.1 268.05 38.95 256.45 31.1 242.4 23.2 228.35 19.1 212.75 15.3 198.16 14.95 183.05 15.53 152.65 27.25 124.4 39.5 94.8 62.2 72.15 84.85 49.45 114.45 37.2 142.94 25.38 173.65 24.9 204.36 25.38 232.8 37.2 262.45 49.45 285.1 72.15 307.75 94.8 320.05 124.4 331.76 152.75 332.3 183.3
L 332.3 218
M 234.25 188.1
Q 234.25 186.15 232.9 184.75 231.5 183.4 229.6 183.35
L 229.25 183.35
Q 227.8 183.45 226.65 184.35
L 176.7 222.2 126.8 184.3
Q 125.9 183.6 124.75 183.4 123.65 183.2 122.55 183.5 121.45 183.85 120.6 184.65 119.8 185.4 119.4 186.5 119.05 187.6 119.2 188.7 119.4 189.85 120.05 190.8
L 172.85 266.35
Q 173.5 267.3 174.55 267.8 175.55 268.35 176.7 268.35 177.85 268.35 178.9 267.8 179.95 267.3 180.6 266.35
L 233.35 190.85
Q 234.25 189.65 234.25 188.1
M 174.4 77.35
Q 173.3 77.95 172.65 79.05
L 123.9 160.15
Q 123 161.75 123.3 163.5 123.65 165.25 125.05 166.35
L 173.85 203.95
Q 175.1 204.95 176.7 204.95 178.3 204.95 179.6 203.95
L 228.35 166.35
Q 229.8 165.25 230.1 163.5 230.45 161.75 229.55 160.15
L 180.75 79.05
Q 180.1 77.95 179.05 77.35 177.95 76.75 176.7 76.75 175.45 76.75 174.4 77.35
M 176.75 136.45
Q 177.6 136.45 178.4 136.8
L 219.8 155.55
Q 221.35 156.25 221.9 157.85 222.5 159.4 221.8 160.95 221.15 162.45 219.55 163.05 217.95 163.65 216.45 162.95
L 178.2 145.65
Q 177.5 145.3 176.7 145.3 175.95 145.3 175.25 145.65
L 137 162.95
Q 135.5 163.65 133.85 163.1 132.3 162.5 131.6 160.95 130.9 159.4 131.5 157.85 132.1 156.25 133.65 155.55
L 175.05 136.8
Q 175.85 136.45 176.75 136.45 Z"
      />
    </svg>
  );
}

// ---- Drip dot for streaming animation -------------------------------------------
function DripDot() {
  return <span className="drip" aria-hidden="true" />;
}

// ---- Pillar card ----------------------------------------------------------------

interface PillarProps {
  accent: string;                // CSS color value
  accentDim: string;             // CSS color for tinted background
  borderColor: string;           // CSS border color
  icon: React.ReactNode;
  title: string;
  body: string;
  ctaLabel: string;
  section: Section;
  onNavigate: (s: Section) => void;
  highlightClass?: string;       // extra class on the CTA button
}

function PillarCard({
  accent,
  accentDim,
  borderColor,
  icon,
  title,
  body,
  ctaLabel,
  section,
  onNavigate,
  highlightClass,
}: PillarProps) {
  return (
    <div
      className="card"
      style={{
        background: accentDim,
        borderColor,
        display: "flex",
        flexDirection: "column",
        gap: "0.85rem",
        marginBottom: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "0.65rem" }}>
        <span style={{ flexShrink: 0, lineHeight: 0 }}>{icon}</span>
        <span
          style={{
            fontWeight: 700,
            fontSize: "15px",
            color: "var(--ink)",
            letterSpacing: "-0.02em",
          }}
        >
          {title}
        </span>
      </div>

      <p
        style={{
          margin: 0,
          fontSize: "0.84rem",
          lineHeight: 1.65,
          color: "var(--muted)",
          flex: 1,
        }}
      >
        {body}
      </p>

      <button
        className={`primary${highlightClass ? ` ${highlightClass}` : ""}`}
        style={
          highlightClass
            ? undefined
            : {
                background: `linear-gradient(180deg, ${accent}cc, ${accent})`,
                color: "#07080c",
              }
        }
        onClick={() => onNavigate(section)}
      >
        {ctaLabel}
      </button>
    </div>
  );
}

// ---- Home component -------------------------------------------------------------

export interface HomeProps {
  /** Live streaming balance display string, e.g. "1234.56789012 UBI" */
  display: string;
  /** Whether the dev account is PoH-verified */
  isVerified: boolean;
  /** Connection status */
  conn: "connecting" | "ok" | "bad";
  /** Navigate to another section */
  onNavigate: (s: Section) => void;
}

export function Home({ display, isVerified, conn, onNavigate }: HomeProps) {
  const balanceNum = display !== "—" ? display : null;

  return (
    <div>
      {/* ---- Hero -------------------------------------------------------- */}
      <div
        className="card"
        style={{
          marginBottom: "18px",
          padding: "36px 32px 32px",
          background: "var(--glass)",
        }}
      >
        {/* Status pill */}
        <div style={{ marginBottom: "18px" }}>
          <span
            className="tag green"
            style={{ fontSize: "11px", letterSpacing: "0.1em" }}
          >
            devnet live
          </span>
          {isVerified && (
            <span
              className="verified-badge poh"
              style={{ marginLeft: "10px", fontSize: "12px" }}
            >
              Verified human
            </span>
          )}
        </div>

        {/* Headline */}
        <h1
          style={{
            margin: "0 0 10px",
            fontSize: "clamp(26px, 5vw, 44px)",
            fontWeight: 800,
            lineHeight: 1.12,
            letterSpacing: "-0.03em",
            color: "var(--ink)",
          }}
        >
          A UBI blockchain where
          <br />
          <span
            style={{
              background: "linear-gradient(135deg, #4fe7a8, #8b7bff)",
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              color: "transparent",
            }}
          >
            citizens are verified humans
          </span>
        </h1>

        <p
          style={{
            margin: "0 0 24px",
            fontSize: "0.96rem",
            lineHeight: 1.65,
            color: "var(--muted)",
            maxWidth: "560px",
          }}
        >
          One verified identity per person. One UBI per hour, streamed continuously. Smart
          contracts written in plain language. All on a real peer-to-peer chain.
        </p>

        {/* Live streaming balance */}
        <div
          style={{
            marginBottom: "28px",
            padding: "18px 22px",
            background: "rgba(79,231,168,0.06)",
            border: "1px solid rgba(79,231,168,0.2)",
            borderRadius: "12px",
            display: "inline-block",
            minWidth: "280px",
          }}
        >
          <div className="label" style={{ marginBottom: "6px" }}>
            Streaming balance · live
          </div>
          <div className="hero-bal" style={{ fontSize: "clamp(28px, 5vw, 46px)", margin: 0 }}>
            {balanceNum ?? "—"}
            <span className="hero-unit">UBI</span>
          </div>
          <div style={{ marginTop: "10px" }}>
            <span className="rate-badge">
              <DripDot />
              +1 UBI / hour · accruing now
            </span>
          </div>
          {!balanceNum && conn !== "ok" && (
            <p style={{ margin: "8px 0 0", fontSize: "0.75rem", color: "var(--warn)" }}>
              {conn === "connecting" ? "Connecting to devnet…" : "Node unreachable — start the devnet node."}
            </p>
          )}
        </div>

        {/* Primary CTAs */}
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
          <button
            className="primary"
            style={{ fontSize: "0.9rem", padding: "0.75rem 1.6rem" }}
            onClick={() => onNavigate("wallet")}
          >
            Open Wallet
          </button>
          <button
            className="primary poh"
            style={{ fontSize: "0.9rem", padding: "0.75rem 1.6rem" }}
            onClick={() => onNavigate("identity")}
          >
            Get verified
          </button>
        </div>
      </div>

      {/* ---- Four pillars ------------------------------------------------------ */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "14px",
          marginBottom: "18px",
        }}
      >
        {/* 1 — Proof of Humanity */}
        <PillarCard
          accent="#ff6699"
          accentDim="rgba(255,255,0,0.025)"
          borderColor="rgba(255,102,153,0.22)"
          icon={<PohMark size={28} />}
          title="Proof of Humanity"
          body="Every UBI recipient is a unique verified human — no bots, no duplicates. Verification happens through social vouching and an AI-jury quorum. Once verified, you earn continuously."
          ctaLabel="Verify identity"
          section="identity"
          onNavigate={onNavigate}
          highlightClass="poh"
        />

        {/* 2 — Streaming UBI */}
        <PillarCard
          accent="#4fe7a8"
          accentDim="rgba(79,231,168,0.04)"
          borderColor="rgba(79,231,168,0.18)"
          icon={
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true">
              <circle cx="14" cy="14" r="13" stroke="#4fe7a8" strokeWidth="1.5" />
              <path d="M8 14 Q14 8 20 14 Q14 20 8 14Z" fill="rgba(79,231,168,0.2)" stroke="#4fe7a8" strokeWidth="1.2" />
              <circle cx="14" cy="14" r="2.5" fill="#4fe7a8" />
            </svg>
          }
          title="Streaming UBI"
          body="Your balance doesn't wait for a monthly payment. It streams at 1 UBI per hour, updating every second. The wallet shows it ticking upward in real time."
          ctaLabel="Open Wallet"
          section="wallet"
          onNavigate={onNavigate}
        />

        {/* 3 — Prompt Contracts */}
        <PillarCard
          accent="#8b7bff"
          accentDim="rgba(139,123,255,0.04)"
          borderColor="rgba(139,123,255,0.18)"
          icon={
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true">
              <rect x="1" y="1" width="26" height="26" rx="6" stroke="#8b7bff" strokeWidth="1.5" />
              <path d="M7 9h14M7 14h10M7 19h7" stroke="#8b7bff" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
          }
          title="Prompt Contracts"
          body="Write contracts in plain English. An interpreter quorum translates your prompt into deterministic on-chain effects — all nodes must agree before anything commits."
          ctaLabel="Deploy a contract"
          section="contracts"
          onNavigate={onNavigate}
          highlightClass="violet"
        />

        {/* 4 — Network Explorer */}
        <PillarCard
          accent="#9ec1ff"
          accentDim="rgba(99,138,255,0.04)"
          borderColor="rgba(99,138,255,0.18)"
          icon={
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true">
              <path d="M14 3 L25 10 L25 20 L14 25 L3 20 L3 10 Z" stroke="#9ec1ff" strokeWidth="1.5" fill="none" />
              <circle cx="14" cy="14" r="2.5" fill="#9ec1ff" />
              <line x1="14" y1="3" x2="14" y2="25" stroke="#9ec1ff" strokeWidth="0.8" strokeDasharray="2 2" />
              <line x1="3" y1="10" x2="25" y2="20" stroke="#9ec1ff" strokeWidth="0.8" strokeDasharray="2 2" />
              <line x1="3" y1="20" x2="25" y2="10" stroke="#9ec1ff" strokeWidth="0.8" strokeDasharray="2 2" />
            </svg>
          }
          title="Network Explorer"
          body="Browse blocks and transactions on the ubi2 devnet. Every stream event, vouch, challenge, and contract invocation is recorded on-chain and inspectable here."
          ctaLabel="Explore blocks"
          section="explorer"
          onNavigate={onNavigate}
        />
      </div>

      {/* ---- AI / LLM setup callout -------------------------------------------- */}
      <div
        className="card violet"
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "1rem",
          marginBottom: "18px",
        }}
      >
        <div
          style={{
            flexShrink: 0,
            width: "38px",
            height: "38px",
            borderRadius: "10px",
            background: "rgba(139,123,255,0.15)",
            border: "1px solid rgba(139,123,255,0.3)",
            display: "grid",
            placeItems: "center",
            fontSize: "18px",
          }}
          aria-hidden="true"
        >
          &#x2728;
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              fontWeight: 700,
              fontSize: "14px",
              color: "var(--accent-2)",
              marginBottom: "5px",
              letterSpacing: "-0.01em",
            }}
          >
            AI / LLM setup
          </div>
          <p
            style={{
              margin: "0 0 12px",
              fontSize: "0.82rem",
              lineHeight: 1.6,
              color: "var(--muted)",
            }}
          >
            Proof-of-humanity verdicts and prompt-contract interpretation both run through an LLM
            quorum. Configure your provider (Anthropic, Ollama, or OpenAI-compatible) and API key
            here before using those features.
          </p>
          <button className="primary violet" onClick={() => onNavigate("ai")}>
            Configure AI backend
          </button>
        </div>
      </div>

      {/* ---- Footer note ------------------------------------------------------- */}
      <p
        style={{
          textAlign: "center",
          fontSize: "0.74rem",
          color: "var(--faint)",
          margin: "8px 0 0",
          lineHeight: 1.6,
        }}
      >
        Chain ID 21826 &middot; EVM-compatible &middot; Add to MetaMask under the Wallet tab
      </p>
    </div>
  );
}
