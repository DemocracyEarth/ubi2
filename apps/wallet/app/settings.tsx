"use client";

/**
 * Settings panel — configure the node's LLM backend via the admin RPC.
 * ubi_getOracleConfig (read) + ubi_setOracleConfig (write).
 * Both are localhost-only; the loopback error is surfaced gracefully.
 */

import { useCallback, useEffect, useState } from "react";
import { Ubi2Client, OracleAdminClient, type OracleConfigResponse } from "@ubi2/sdk";
import { RPC_URL } from "./config";

const client = new Ubi2Client({ url: RPC_URL });
const oracle = new OracleAdminClient(client);

const LOOPBACK_ERR = "localhost-only";

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "object" && e !== null) {
    const o = e as Record<string, unknown>;
    const m = o.shortMessage ?? o.message;
    if (typeof m === "string") return m;
  }
  return String(e);
}

interface SettingsProps {
  onClose: () => void;
}

export function Settings({ onClose }: SettingsProps) {
  const [cfg, setCfg] = useState<OracleConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [loopbackOnly, setLoopbackOnly] = useState(false);

  // Form
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
      setApiKey(""); // clear raw key from memory
      setSaveNote({ kind: "ok", text: `Config applied · active: ${r.active} · ${r.health.provider}` });
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
      setSaveNote({ kind: "ok", text: "Reverted to deterministic Mock mode." });
    } catch (e) {
      setSaveNote({ kind: "err", text: errMsg(e) });
    } finally {
      setSaving(false);
    }
  }, []);

  // Health dot style
  const healthCls = !cfg
    ? "mock"
    : cfg.health.reachable
      ? "ok"
      : cfg.active === "mock"
        ? "mock"
        : "bad";

  return (
    <aside className="settings-panel">
      <button className="close-btn" onClick={onClose}>close</button>
      <h3>⚙ LLM Backend</h3>

      {loopbackOnly && (
        <div className="notice err">
          Admin RPC is localhost-only. Open the wallet at <code>http://127.0.0.1:3000</code> (not{" "}
          <code>localhost</code> or any remote URL) to configure the node's LLM backend.
        </div>
      )}

      {!loopbackOnly && loading && (
        <p className="muted small">Loading oracle config…</p>
      )}

      {!loopbackOnly && err && (
        <div className="notice err">{err}</div>
      )}

      {!loopbackOnly && cfg && (
        <>
          {/* Current health */}
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>Current status</h2>
            <div className="health-row">
              <span className={`health-dot ${healthCls}`} />
              <span style={{ fontFamily: "var(--mono)", fontSize: ".82rem", color: "var(--ink)" }}>
                {cfg.health.provider || "mock"}
                {cfg.health.model ? ` · ${cfg.health.model}` : ""}
              </span>
              <span className="faint small" style={{ marginLeft: "auto" }}>
                {cfg.active === "live"
                  ? cfg.health.reachable ? "reachable" : "unreachable"
                  : "deterministic"}
              </span>
            </div>
            {cfg.health.error && (
              <div className="notice err" style={{ marginTop: ".5rem", fontSize: ".75rem" }}>
                {cfg.health.error}
              </div>
            )}
          </div>

          {/* Config form */}
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
                  (in-memory only · never persisted)
                </span>
              </label>
              <input
                type="password"
                placeholder="sk-ant-… or sk-…"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                autoComplete="off"
              />
            </div>
          )}

          <div style={{ display: "flex", gap: ".5rem", marginTop: ".25rem" }}>
            <button className="primary violet" onClick={save} disabled={saving}>
              {saving ? "Applying…" : "Apply config"}
            </button>
            {cfg.active !== "mock" && (
              <button className="ghost" onClick={clearToMock} disabled={saving}>
                Revert to Mock
              </button>
            )}
          </div>

          {saveNote && (
            <div className={`notice ${saveNote.kind}`}>{saveNote.text}</div>
          )}

          <div className="muted small" style={{ marginTop: "1.25rem", lineHeight: 1.6 }}>
            The raw API key is used to build the backend and then discarded — only the env-var
            name is persisted to disk (I6). Changes take effect at the next block boundary.
          </div>
        </>
      )}
    </aside>
  );
}
