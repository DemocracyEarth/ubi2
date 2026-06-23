"use client";

/**
 * Obsidian-glass sticky nav: brand dot, tab rail, connection pill, settings gear.
 */

export type Section = "wallet" | "explorer" | "identity" | "contracts";

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
];

export function Nav({ active, onSelect, conn, chainId, onSettings, settingsOpen }: NavProps) {
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

      {/* Settings gear */}
      <button
        className={`gear-btn ${settingsOpen ? "active" : ""}`}
        title="Settings — configure the node's LLM backend (Ollama / Anthropic / OpenAI)"
        onClick={onSettings}
        aria-label="Settings"
      >
        ⚙
      </button>
    </div>
  );
}
