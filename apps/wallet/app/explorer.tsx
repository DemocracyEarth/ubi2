"use client";

/**
 * M4 block explorer section: search by address or tx hash, latest blocks, and a
 * per-account view powered by the EXPL-1 indexer (ubi_getAccount + ubi_getAddressActivity).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  ExplorerReader,
  formatUbi,
  type Block,
  type AccountSummary,
  type ActivityRow,
} from "@ubi2/sdk";
import { RPC_URL } from "./config";

const client = new Ubi2Client({ url: RPC_URL });
const explorer = new ExplorerReader(client);

const MAX_BLOCKS = 8;
const POLL_MS = 4000;

function shortHash(h: string): string {
  if (!h || h.length < 14) return h;
  return `${h.slice(0, 8)}…${h.slice(-6)}`;
}

function shortAddr(a: string): string {
  if (!a || a.length < 12) return a;
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

function fmtTs(hexSecs: string): string {
  const secs = parseInt(hexSecs, 16);
  if (!Number.isFinite(secs)) return "—";
  return new Date(secs * 1000).toLocaleTimeString();
}

function hexToUbi(hex: string): string {
  try {
    return formatUbi(BigInt(hex), 4);
  } catch {
    return "0.0000 UBI";
  }
}

function kindBadge(kind: string): { label: string; cls: string } {
  if (kind === "Transfer") return { label: "Transfer", cls: "pill completed" };
  if (kind === "OpenStream") return { label: "Open Stream", cls: "pill active" };
  if (kind === "StopStream") return { label: "Stop Stream", cls: "pill stopped" };
  if (kind === "RequestVerification") return { label: "Apply PoH", cls: "pill poh-pending" };
  if (kind === "Vouch") return { label: "Vouch", cls: "pill active" };
  if (kind === "Challenge") return { label: "Challenge", cls: "pill poh-challenged" };
  if (kind === "SubmitVerdict") return { label: "Verdict", cls: "pill completed" };
  if (kind === "DeployContract") return { label: "Deploy Contract", cls: "pill active" };
  if (kind === "FundContract") return { label: "Fund Contract", cls: "pill active" };
  if (kind === "InvokeContract") return { label: "Invoke Contract", cls: "pill poh-pending" };
  if (kind === "SubmitEffect") return { label: "Submit Effect", cls: "pill completed" };
  return { label: kind, cls: "pill completed" };
}

function Copy({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="copy"
      style={{ fontSize: "0.7rem", padding: "0.2rem 0.5rem" }}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch { /* unavailable */ }
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

/** Account view panel — shown when an address is searched or clicked. */
function AccountView({ address, onClose }: { address: string; onClose: () => void }) {
  const [summary, setSummary] = useState<AccountSummary | null>(null);
  const [activity, setActivity] = useState<ActivityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const [s, a] = await Promise.all([
        explorer.getAccount(address),
        explorer.getAddressActivity(address, 30),
      ]);
      setSummary(s);
      setActivity(a);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [address]);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  const humanStatusCls =
    summary?.human_status === "Verified"
      ? "pill active"
      : summary?.human_status === "Pending"
        ? "pill poh-pending"
        : summary?.human_status === "Challenged"
          ? "pill poh-challenged"
          : "pill completed";

  return (
    <section className="card" style={{ marginTop: "1.25rem" }}>
      <div className="row" style={{ marginBottom: "0.85rem" }}>
        <h2 style={{ margin: 0 }}>Account</h2>
        <button className="ghost" onClick={onClose} style={{ fontSize: "0.75rem" }}>
          Clear
        </button>
      </div>

      {loading && !summary && <p className="muted small">Loading…</p>}
      {err && <p className="small" style={{ color: "var(--danger)" }}>{err}</p>}

      {summary && (
        <>
          {/* Address */}
          <div className="field" style={{ marginBottom: "0.75rem" }}>
            <div className="label">Address</div>
            <div className="row" style={{ marginTop: "0.2rem" }}>
              <span className="addr" style={{ fontSize: "0.8rem", wordBreak: "break-all" }}>
                {address}
              </span>
              <Copy value={address} />
            </div>
          </div>

          {/* Stats grid */}
          <div className="acct-grid">
            <div className="acct-stat">
              <div className="label">Balance</div>
              <div className="acct-val">{hexToUbi(summary.balance)}</div>
            </div>
            <div className="acct-stat">
              <div className="label">Nonce</div>
              <div className="acct-val">{parseInt(summary.nonce, 16)}</div>
            </div>
            <div className="acct-stat">
              <div className="label">Identity</div>
              <div className="acct-val">
                {summary.human_status ? (
                  <span className={humanStatusCls} style={{ fontSize: "0.75rem" }}>
                    {summary.human_status}
                  </span>
                ) : (
                  <span className="muted small">—</span>
                )}
              </div>
            </div>
            <div className="acct-stat">
              <div className="label">Streams in / out</div>
              <div className="acct-val">
                {summary.streams_in} / {summary.streams_out}
              </div>
            </div>
            <div className="acct-stat">
              <div className="label">Contracts</div>
              <div className="acct-val">{summary.contracts}</div>
            </div>
            <div className="acct-stat">
              <div className="label">Tx count</div>
              <div className="acct-val">{summary.tx_count}</div>
            </div>
          </div>

          {/* Activity feed */}
          <div style={{ marginTop: "1rem" }}>
            <div className="label" style={{ marginBottom: "0.5rem" }}>
              Recent activity ({activity.length})
            </div>
            {activity.length === 0 ? (
              <p className="muted small">No activity yet.</p>
            ) : (
              <div className="activity-list">
                {activity.map((row, i) => {
                  const badge = kindBadge(row.kind);
                  const counterparty = row.counterparty;
                  const blockNum = parseInt(row.blockNumber, 16);
                  return (
                    <div className="activity-row" key={`${row.hash}-${i}`}>
                      <span className={badge.cls} style={{ minWidth: "6rem", textAlign: "center" }}>
                        {badge.label}
                      </span>
                      <span className="block-num">#{blockNum}</span>
                      <span className="block-hash">{shortHash(row.hash)}</span>
                      {counterparty && (
                        <span className="muted small">{shortAddr(counterparty)}</span>
                      )}
                      {row.value !== "0x0" && row.value !== "0x00" && (
                        <span className="muted small">{hexToUbi(row.value)}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

export function Explorer() {
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [latest, setLatest] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [searched, setSearched] = useState<string | null>(null);
  const [searchType, setSearchType] = useState<"address" | "tx" | null>(null);
  const [txResult, setTxResult] = useState<Record<string, unknown> | null>(null);
  const [txErr, setTxErr] = useState<string | null>(null);

  const pollRef = useRef<() => void>(() => {});

  const refresh = useCallback(async () => {
    try {
      const head = await client.blockNumber();
      setLatest(head);
      const start = Math.max(0, head - (MAX_BLOCKS - 1));
      const nums: number[] = [];
      for (let n = head; n >= start; n--) nums.push(n);
      const fetched = await Promise.all(nums.map((n) => client.getBlockByNumber(n)));
      setBlocks(fetched.filter((b): b is Block => b != null));
    } catch {
      /* node may be down */
    }
  }, []);
  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    const id = setInterval(() => pollRef.current(), POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const search = useCallback(async () => {
    const q = query.trim();
    if (!q) return;

    // Detect type: 66-char hex = tx hash (0x + 64); 42-char = address
    if (/^0x[0-9a-fA-F]{64}$/.test(q)) {
      setSearchType("tx");
      setSearched(q);
      setTxResult(null);
      setTxErr(null);
      try {
        const res = await client.call<Record<string, unknown> | null>(
          "eth_getTransactionByHash",
          [q],
        );
        if (res) setTxResult(res);
        else setTxErr("Transaction not found.");
      } catch (e) {
        setTxErr(e instanceof Error ? e.message : String(e));
      }
    } else if (/^0x[0-9a-fA-F]{40}$/.test(q)) {
      setSearchType("address");
      setSearched(q);
      setTxResult(null);
      setTxErr(null);
    } else {
      setTxErr("Enter a 0x address (42 chars) or tx hash (66 chars).");
      setSearchType(null);
      setSearched(null);
    }
  }, [query]);

  const clearSearch = useCallback(() => {
    setSearched(null);
    setSearchType(null);
    setTxResult(null);
    setTxErr(null);
    setQuery("");
  }, []);

  return (
    <div>
      {/* Search */}
      <section className="card">
        <h2>Explorer</h2>
        <div className="row" style={{ gap: "0.5rem", flexWrap: "nowrap" }}>
          <input
            style={{
              flex: 1,
              background: "var(--panel-2)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
              color: "var(--fg)",
              fontFamily: "var(--mono)",
              fontSize: "0.85rem",
              padding: "0.6rem 0.75rem",
              outline: "none",
              minWidth: 0,
            }}
            placeholder="Search address (0x…40) or tx hash (0x…64)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
            spellCheck={false}
          />
          <button className="primary" onClick={search} style={{ whiteSpace: "nowrap" }}>
            Search
          </button>
        </div>
        {txErr && !searched && (
          <p className="small" style={{ color: "var(--danger)", marginTop: "0.5rem" }}>
            {txErr}
          </p>
        )}
      </section>

      {/* Tx result */}
      {searchType === "tx" && searched && (
        <section className="card">
          <div className="row" style={{ marginBottom: "0.75rem" }}>
            <h2 style={{ margin: 0 }}>Transaction</h2>
            <button className="ghost" onClick={clearSearch} style={{ fontSize: "0.75rem" }}>
              Clear
            </button>
          </div>
          {txErr && <p className="small" style={{ color: "var(--danger)" }}>{txErr}</p>}
          {txResult && (
            <dl className="kv">
              <dt>Hash</dt>
              <dd style={{ wordBreak: "break-all" }}>{String(txResult.hash ?? "—")}</dd>
              <dt>Block</dt>
              <dd>#{parseInt(String(txResult.blockNumber ?? "0"), 16)}</dd>
              <dt>From</dt>
              <dd style={{ wordBreak: "break-all" }}>{String(txResult.from ?? "—")}</dd>
              <dt>To</dt>
              <dd style={{ wordBreak: "break-all" }}>{String(txResult.to ?? "—")}</dd>
              <dt>Value</dt>
              <dd>{hexToUbi(String(txResult.value ?? "0x0"))}</dd>
              <dt>Nonce</dt>
              <dd>{parseInt(String(txResult.nonce ?? "0x0"), 16)}</dd>
              <dt>Input</dt>
              <dd style={{ wordBreak: "break-all", fontSize: "0.72rem" }}>
                {String(txResult.input ?? "0x")}
              </dd>
            </dl>
          )}
        </section>
      )}

      {/* Address account view */}
      {searchType === "address" && searched && (
        <AccountView address={searched} onClose={clearSearch} />
      )}

      {/* Latest blocks */}
      <section className="card">
        <div className="row" style={{ marginBottom: "0.75rem" }}>
          <h2 style={{ margin: 0 }}>Latest blocks</h2>
          <span className="block-num">{latest != null ? `#${latest}` : "—"}</span>
        </div>
        {blocks.length === 0 ? (
          <p className="muted small">No blocks yet.</p>
        ) : (
          <div className="blocks">
            {blocks.map((b) => {
              const num = parseInt(b.number, 16);
              const txCount =
                Array.isArray(b.transactions) ? b.transactions.length : 0;
              return (
                <div className="block-row" key={b.hash || b.number}>
                  <span className="block-num">#{num}</span>
                  <span className="block-hash">{shortHash(b.hash)}</span>
                  <span className="muted small">{txCount} tx{txCount !== 1 ? "s" : ""}</span>
                  <span className="block-ts">{fmtTs(b.timestamp)}</span>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
