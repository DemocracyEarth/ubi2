"use client";

/**
 * Obsidian-glass sticky nav: brand dot, tab rail, connection pill.
 * "AI" is now a first-class tab alongside Wallet / Explorer / Identity / Contracts.
 * The gear button is kept for quick-access but AI section is the primary settings home.
 */

export type Section = "wallet" | "explorer" | "identity" | "contracts" | "ai";

interface NavProps {
  active: Section;
  onSelect: (s: Section) => void;
  conn: "connecting" | "ok" | "bad";
  chainId: number | null;
  onSettings: () => void;
  settingsOpen: boolean;
}

const TABS: { id: Section; label: string; violet?: boolean }[] = [
  { id: "wallet", label: "Wallet" },
  { id: "explorer", label: "Explorer" },
  { id: "identity", label: "Identity" },
  { id: "contracts", label: "Contracts", violet: true },
  { id: "ai", label: "AI", violet: true },
];

export function Nav({ active, onSelect, conn, chainId }: NavProps) {
  const pillClass =
    conn === "ok" ? "conn-pill ok" : conn === "bad" ? "conn-pill bad" : "conn-pill warn";
  const pillText =
    conn === "ok"
      ? `devnet · ${chainId ?? "…"}`
      : conn === "connecting"
        ? "connecting…"
        : "disconnected";

  return (
    <div className="top-nav">
      {/* Brand */}
      <div className="brand">
        <span className="brand-dot" />
        <span>UBI</span>
      </div>

      {/* Tab rail */}
      <nav className="nav-tabs">
        {TABS.map((t) => {
          const isActive = active === t.id;
          const cls = isActive
            ? t.violet
              ? "nav-tab active-violet"
              : "nav-tab active"
            : "nav-tab";
          return (
            <button key={t.id} className={cls} onClick={() => onSelect(t.id)}>
              {t.label}
            </button>
          );
        })}
      </nav>

      <div className="nav-spacer" />

      {/* Connection pill */}
      <span className={pillClass}>
        <span className="conn-dot" />
        {pillText}
      </span>
    </div>
  );
}
