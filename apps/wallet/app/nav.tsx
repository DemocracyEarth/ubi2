"use client";

/**
 * Top navigation bar — switches between the four app sections (Wallet, Explorer, Identity,
 * Contracts) via a simple tab state passed down from the root.  No router needed: the whole
 * app is a single page with section-based rendering, which keeps the streaming balance alive
 * across tab switches without remounting.
 */

export type Section = "wallet" | "explorer" | "identity" | "contracts";

interface NavProps {
  active: Section;
  onSelect: (s: Section) => void;
  conn: "connecting" | "ok" | "bad";
  chainId: number | null;
}

const TABS: { id: Section; label: string }[] = [
  { id: "wallet", label: "Wallet" },
  { id: "explorer", label: "Explorer" },
  { id: "identity", label: "Identity" },
  { id: "contracts", label: "Contracts" },
];

export function Nav({ active, onSelect, conn, chainId }: NavProps) {
  const statusClass =
    conn === "ok" ? "status ok" : conn === "bad" ? "status bad" : "status warn";
  const statusText =
    conn === "ok"
      ? `Connected · chain ${chainId}`
      : conn === "connecting"
        ? "Connecting…"
        : "Disconnected";

  return (
    <div className="top-nav">
      <div className="top-nav-inner">
        <div className="brand">
          <span className="brand-name">
            ubi<span style={{ color: "var(--accent)" }}>2</span>
          </span>
          <span className="brand-tag">devnet</span>
        </div>

        <nav className="nav-tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`nav-tab ${active === t.id ? "active" : ""}`}
              onClick={() => onSelect(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <span className={statusClass} style={{ fontSize: "0.75rem" }}>
          <span className="dot" />
          {statusText}
        </span>
      </div>
    </div>
  );
}
