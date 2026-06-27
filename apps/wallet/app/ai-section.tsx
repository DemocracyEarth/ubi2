"use client";

/**
 * AI section — first-class nav tab showing the node's LLM backend status.
 *
 * Displays prominently:
 *  - ACTIVE provider (Anthropic / Ollama / OpenAI / Mock) with a large status indicator
 *  - The model in use
 *  - Masked API key (e.g. sk-ant-...AB12) — never the full secret
 *  - Reachability / health status line
 *  - Edit / save flow (loopback-only oracle-admin)
 */

import { useCallback, useEffect, useState } from "react";
import { Ubi2Client, OracleAdminClient, type OracleConfigResponse } from "@ubi2/sdk";
import { RPC_URL } from "./config";

const client = new Ubi2Client({ url: RPC_URL });
const oracle = new OracleAdminClient(client);

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (e && typeof e === "object") {
    const o = e as Record<string, unknown>;
    const m = o.shortMessage ?? o.message;
    if (typeof m === "string") return m;
  }
  return String(e);
}

/** Mask an API key: keep first 10 chars + "..." + last 4 chars. */
function maskKey(keyEnv: string | undefined): string {
  if (!keyEnv) return "—";
  // keyEnv is the env var NAME e.g. "ANTHROPIC_API_KEY", not the value
  // The node returns REDACTED for the actual value, so we show the env var name
  return keyEnv;
}

function providerLabel(provider: string | undefined): string {
  if (!provider) return "Mock (deterministic)";
  const map: Record<string, string> = {
    anthropic: "Anthropic",
    ollama: "Ollama (local)",
    openai: "OpenAI-compatible",
  };
  return map[provider] ?? provider;
}

function providerColor(provider: string | undefined, active: string): string {
  if (active === "mock" || !provider) return "var(--warn)";
  return "var(--accent)";
}

export function AiSection() {
  const [cfg, setCfg] = useState<OracleConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [loopbackOnly, setLoopbackOnly] = useState(false);

  // Edit form
  const [editing, setEditing] = useState(false);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveNote, setSaveNote] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const r = await oracle.getConfig();
      setCfg(r);
      setProvider(r.config.provider ?? "");
      setModel(r.config.model ?? "");
      setBaseUrl(r.config.base_url ?? "");
    } catch (e) {
      const msg = errMsg(e);
      if (msg.includes("localhost-only") || msg.includes("-32099")) {
        setLoopbackOnly(true);
      } else {
        setErr(msg);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = useCallback(async () => {
    setSaving(true);
    setSaveNote(null);
    try {
      const r = await oracle.setConfig({
        provider: provider || undefined,
        model: model || undefined,
        base_url: baseUrl || undefined,
        api_key: apiKey || undefined,
      });
      setCfg(r);
      setApiKey("");
      setEditing(false);
      setSaveNote({ kind: "ok", text: `Config applied — active: ${r.active} · ${r.health.provider}` });
    } catch (e) {
      setSaveNote({ kind: "err", text: errMsg(e) });
    } finally {
      setSaving(false);
    }
  }, [provider, model, baseUrl, apiKey]);

  const clearToMock = useCallback(async () => {
    setSaving(true);
    setSaveNote(null);
    try {
      const r = await oracle.setConfig({});
      setCfg(r);
      setProvider(""); setModel(""); setBaseUrl(""); setApiKey("");
      setEditing(false);
      setSaveNote({ kind: "ok", text: "Reverted to deterministic Mock mode." });
    } catch (e) {
      setSaveNote({ kind: "err", text: errMsg(e) });
    } finally {
      setSaving(false);
    }
  }, []);

  const isMock = !cfg || cfg.active === "mock";
  const isReachable = cfg?.health.reachable ?? false;

  return (
    <div>
      {/* Header */}
      <section className="card">
        <div className="card-header" style={{ marginBottom: "0.5rem" }}>
          <h2 style={{ margin: 0 }}>AI Backend</h2>
          <span className="tag violet" style={{ fontSize: "0.62rem" }}>oracle config</span>
        </div>
        <div className="muted small" style={{ lineHeight: 1.55 }}>
          The node uses an AI interpreter (LLM) to evaluate proof-of-humanity verdicts and
          interpret prompt contracts. This panel shows which backend is active and lets you
          switch providers (localhost admin only).
        </div>
      </section>

      {/* Active provider status — prominent display */}
      <section className="card" style={isMock ? { border: "1px solid rgba(251,191,92,.3)" } : { border: "1px solid rgba(79,231,168,.3)" }}>
        <div className="label" style={{ marginBottom: "1rem" }}>Active provider</div>

        {loading && (
          <p className="muted small">Loading oracle config…</p>
        )}

        {loopbackOnly && !loading && (
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.85rem",
                marginBottom: "1rem",
              }}
            >
              <div
                style={{
                  width: "48px",
                  height: "48px",
                  borderRadius: "12px",
                  background: "rgba(251,191,92,.12)",
                  border: "1px solid rgba(251,191,92,.3)",
                  display: "grid",
                  placeItems: "center",
                  fontSize: "1.5rem",
                  flexShrink: 0,
                }}
              >
                ◈
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: "1.1rem", color: "var(--warn)", marginBottom: "0.2rem" }}>
                  Unknown (admin restricted)
                </div>
                <div className="muted small">
                  Oracle config is only readable from localhost
                </div>
              </div>
            </div>
            <div
              className="notice err"
              style={{ fontSize: "0.78rem" }}
            >
              Admin RPC is localhost-only. Open the wallet at{" "}
              <code style={{ fontFamily: "var(--mono)", background: "rgba(255,255,255,.08)", padding: "1px 5px", borderRadius: "4px" }}>
                http://127.0.0.1:3000
              </code>{" "}
              to configure the node&apos;s LLM backend.
            </div>
          </div>
        )}

        {err && !loading && (
          <div className="notice err">{err}</div>
        )}

        {cfg && !loopbackOnly && (
          <>
            {/* Big provider status indicator */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "1rem",
                marginBottom: "1.25rem",
              }}
            >
              <div
                style={{
                  width: "52px",
                  height: "52px",
                  borderRadius: "14px",
                  background: isMock
                    ? "rgba(251,191,92,.1)"
                    : isReachable
                      ? "rgba(79,231,168,.1)"
                      : "rgba(255,107,107,.1)",
                  border: `1px solid ${isMock ? "rgba(251,191,92,.3)" : isReachable ? "rgba(79,231,168,.3)" : "rgba(255,107,107,.3)"}`,
                  display: "grid",
                  placeItems: "center",
                  fontSize: "1.6rem",
                  flexShrink: 0,
                }}
              >
                {isMock ? "◈" : cfg.config.provider === "anthropic" ? "A" : cfg.config.provider === "ollama" ? "O" : "AI"}
              </div>
              <div style={{ flex: 1 }}>
                <div
                  style={{
                    fontWeight: 800,
                    fontSize: "1.2rem",
                    color: providerColor(cfg.config.provider, cfg.active),
                    marginBottom: "0.2rem",
                    letterSpacing: "-0.02em",
                  }}
                >
                  {providerLabel(cfg.config.provider)}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                  <span
                    style={{
                      display: "inline-block",
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      background: isMock
                        ? "var(--warn)"
                        : isReachable
                          ? "var(--accent)"
                          : "var(--danger)",
                      flexShrink: 0,
                    }}
                  />
                  <span className="muted small">
                    {isMock
                      ? "Deterministic mock — no API calls made"
                      : isReachable
                        ? "Reachable — live AI inference active"
                        : "Unreachable — check config / connectivity"}
                  </span>
                </div>
              </div>
              <button
                className="ghost"
                style={{ fontSize: "0.75rem", flexShrink: 0 }}
                onClick={() => { setEditing(!editing); setSaveNote(null); }}
              >
                {editing ? "Cancel" : "Configure"}
              </button>
            </div>

            {/* Config detail */}
            <dl className="kv" style={{ marginBottom: "0.5rem" }}>
              <dt>Active</dt>
              <dd>
                <span
                  style={{
                    fontFamily: "var(--mono)",
                    fontWeight: 700,
                    color: cfg.active === "live" ? "var(--accent)" : "var(--warn)",
                  }}
                >
                  {cfg.active}
                </span>
              </dd>
              <dt>Provider</dt>
              <dd style={{ fontFamily: "var(--mono)", fontSize: "0.82rem" }}>
                {cfg.health.provider || "mock"}
              </dd>
              <dt>Model</dt>
              <dd style={{ fontFamily: "var(--mono)", fontSize: "0.82rem" }}>
                {cfg.health.model || "—"}
              </dd>
              {cfg.config.api_key_env && (
                <>
                  <dt>API key env</dt>
                  <dd>
                    <span
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: "0.75rem",
                        background: "rgba(139,123,255,.1)",
                        border: "1px solid rgba(139,123,255,.25)",
                        borderRadius: "6px",
                        padding: "2px 7px",
                        color: "var(--accent-2)",
                      }}
                    >
                      {maskKey(cfg.config.api_key_env)}
                    </span>
                    <span className="muted small" style={{ marginLeft: "0.5rem", fontSize: "0.72rem" }}>
                      (env var name — key never logged)
                    </span>
                  </dd>
                </>
              )}
              {cfg.config.base_url && (
                <>
                  <dt>Base URL</dt>
                  <dd style={{ fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--muted)" }}>
                    {cfg.config.base_url}
                  </dd>
                </>
              )}
            </dl>

            {cfg.health.error && (
              <div
                className="notice err"
                style={{ marginTop: "0.5rem", fontSize: "0.75rem" }}
              >
                {cfg.health.error}
              </div>
            )}

            {saveNote && (
              <div className={`notice ${saveNote.kind}`} style={{ marginTop: "0.75rem" }}>
                {saveNote.text}
              </div>
            )}
          </>
        )}
      </section>

      {/* Edit form (only shown when editing=true and not loopback-restricted) */}
      {editing && cfg && !loopbackOnly && (
        <section className="card" style={{ border: "1px solid rgba(139,123,255,.3)" }}>
          <h2 style={{ margin: "0 0 1rem" }}>Configure LLM backend</h2>

          <div className="field">
            <label>Provider</label>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              style={{
                background: "rgba(10,12,18,.7)",
                border: "1px solid var(--line-2)",
                borderRadius: "10px",
                color: "var(--ink)",
                fontFamily: "var(--mono)",
                fontSize: ".85rem",
                padding: ".55rem .75rem",
                outline: "none",
                width: "100%",
              }}
            >
              <option value="">Mock (deterministic — no API calls)</option>
              <option value="anthropic">Anthropic</option>
              <option value="ollama">Ollama (local)</option>
              <option value="openai">OpenAI-compatible</option>
            </select>
          </div>

          <div className="field">
            <label>Model</label>
            <input
              placeholder={
                provider === "anthropic"
                  ? "claude-3-5-haiku-20241022"
                  : provider === "ollama"
                    ? "llama3.1"
                    : provider === "openai"
                      ? "gpt-4o-mini"
                      : "provider default"
              }
              value={model}
              onChange={(e) => setModel(e.target.value)}
            />
          </div>

          {(provider === "ollama" || provider === "openai") && (
            <div className="field">
              <label>Base URL</label>
              <input
                placeholder={
                  provider === "ollama" ? "http://localhost:11434" : "https://api.openai.com/v1"
                }
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
              />
            </div>
          )}

          {(provider === "anthropic" || provider === "openai") && (
            <div className="field">
              <label>
                API Key{" "}
                <span style={{ color: "var(--faint)", textTransform: "none", letterSpacing: 0 }}>
                  (in-memory only · never persisted to disk)
                </span>
              </label>
              <input
                type="password"
                placeholder="sk-ant-… or sk-…"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                autoComplete="off"
              />
              <div className="muted small" style={{ marginTop: "0.3rem", lineHeight: 1.55 }}>
                The key is used to create the backend connection and then discarded from memory.
                Only the env-var name is persisted to disk (never the key value).
              </div>
            </div>
          )}

          <div style={{ display: "flex", gap: ".5rem", marginTop: ".75rem" }}>
            <button className="primary violet" onClick={save} disabled={saving}>
              {saving ? "Applying…" : "Apply config"}
            </button>
            {cfg.active !== "mock" && (
              <button className="ghost" onClick={clearToMock} disabled={saving}>
                Revert to Mock
              </button>
            )}
            <button className="ghost" onClick={() => { setEditing(false); setSaveNote(null); }}>
              Cancel
            </button>
          </div>
        </section>
      )}

      {/* Usage guide */}
      <section className="card">
        <h2 style={{ margin: "0 0 0.75rem" }}>How the AI layer works</h2>
        <div className="muted small" style={{ lineHeight: 1.65 }}>
          <p style={{ margin: "0 0 0.65rem" }}>
            <strong style={{ color: "var(--ink)" }}>Proof-of-Humanity verdicts</strong> — when a
            human review case opens, a quorum of AI interpreters reads the submitted evidence and
            votes on a verdict (Approved / Rejected). The on-chain verdict is committed only when
            the required quorum agrees.
          </p>
          <p style={{ margin: "0 0 0.65rem" }}>
            <strong style={{ color: "var(--ink)" }}>Prompt-contract interpretation</strong> — when
            you invoke a contract with a plain-language trigger, the AI reads the contract text and
            the trigger and commits a deterministic effect (Transfer, Refund, OpenStream, or Abort).
            The mock interpreter always returns a deterministic stub — no real AI is called.
          </p>
          <p style={{ margin: 0 }}>
            <strong style={{ color: "var(--ink)" }}>Switching providers</strong> — configure a
            local Ollama model for air-gapped operation, or supply an Anthropic / OpenAI key for
            cloud inference. Changes take effect at the next block boundary.
          </p>
        </div>
      </section>
    </div>
  );
}
