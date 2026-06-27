"use client";

/**
 * Minimal shell for standalone explorer route pages.
 * Renders the same sticky nav brand + "Back to explorer" link,
 * wraps children in the standard app-main layout.
 */

import Link from "next/link";

export function ExplorerPageShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <>
      {/* Sticky nav */}
      <div className="top-nav">
        <div className="brand">
          <span className="brand-dot" />
          <span>UBI</span>
        </div>
        <div style={{ marginLeft: "1rem", display: "flex", alignItems: "center", gap: ".75rem" }}>
          <Link
            href="/"
            style={{
              fontSize: "13px",
              color: "var(--muted)",
              fontWeight: 500,
              padding: "8px 14px",
              borderRadius: "11px",
              transition: "color .18s, background .18s",
              textDecoration: "none",
            }}
          >
            Wallet
          </Link>
          <Link
            href="/#explorer"
            style={{
              fontSize: "13px",
              color: "var(--ink)",
              fontWeight: 600,
              padding: "8px 14px",
              borderRadius: "11px",
              background: "var(--glass-2)",
              textDecoration: "none",
            }}
          >
            Explorer
          </Link>
        </div>
        <div className="nav-spacer" />
        <Link
          href="/"
          style={{
            fontSize: "13px",
            color: "var(--muted)",
            textDecoration: "none",
            padding: "7px 12px",
            border: "1px solid var(--line)",
            borderRadius: "999px",
            background: "var(--glass)",
            whiteSpace: "nowrap",
          }}
        >
          Back to wallet
        </Link>
      </div>

      <main className="app-main">
        {/* Breadcrumb header */}
        <div style={{ marginBottom: "1.25rem" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: ".5rem",
              marginBottom: ".4rem",
              fontSize: ".8rem",
              color: "var(--faint)",
            }}
          >
            <Link href="/" style={{ color: "var(--faint)", textDecoration: "none" }}>
              Wallet
            </Link>
            <span>/</span>
            <span style={{ color: "var(--muted)" }}>{title}</span>
          </div>
          <h2
            style={{
              margin: 0,
              fontSize: "1.1rem",
              fontWeight: 700,
              color: "var(--ink)",
              letterSpacing: "-.02em",
            }}
          >
            {title}
          </h2>
          {subtitle && (
            <div
              style={{
                fontFamily: "var(--mono)",
                fontSize: ".75rem",
                color: "var(--muted)",
                marginTop: ".25rem",
                wordBreak: "break-all",
              }}
            >
              {subtitle}
            </div>
          )}
        </div>

        {children}
      </main>
    </>
  );
}
