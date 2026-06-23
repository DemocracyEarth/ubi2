"use client";

/**
 * Deep block explorer — obsidian-glass, cycle-5.
 * Search by address / tx hash / block number.
 * Block page: full header fields + decoded tx list (ubi_getBlock).
 * Tx page: from/to/fee, decoded hub call, decoded logs, result (ubi_getTransaction).
 * Account page: ubi_getAccount + ubi_getAddressActivity.
 * Latest blocks list polling every 4 s.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  ExplorerReader,
  formatUbi,
  type Block,
  type AccountSummary,
  type ActivityRow,
  type DecodedBlock,
  type DecodedTransaction,
  type DecodedLog,
} from "@ubi2/sdk";
import { RPC_URL } from "./config";

const client = new Ubi2Client({ url: RPC_URL });
const explorer = new ExplorerReader(client);

const MAX_BLOCKS = 10;
const POLL_MS = 4000;

// ---- Helpers -----------------------------------------------------------------------

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
  const d = new Date(secs * 1000);
  return d.toLocaleTimeString();
}

function fmtTsLong(hexSecs: string): string {
  const secs = parseInt(hexSecs, 16);
  if (!Number.isFinite(secs)) return "—";
  return new Date(secs * 1000).toLocaleString();
}

function hexToUbi(hex: string, frac = 4): string {
  try {
    return formatUbi(BigInt(hex), frac);
  } catch {
    return "0 UBI";
  }
}

function parseBlockNum(s: string): number {
  if (s.startsWith("0x")) return parseInt(s, 16);
  return parseInt(s, 10);
}

function kindBadge(kind: string): { label: string; cls: string } {
  const map: Record<string, { label: string; cls: string }> = {
    Transfer: { label: "transfer", cls: "kind-badge k-transfer" },
    OpenStream: { label: "open stream", cls: "kind-badge k-stream" },
    StopStream: { label: "stop stream", cls: "kind-badge k-stream" },
    RequestVerification: { label: "apply PoH", cls: "kind-badge k-humanity" },
    Vouch: { label: "vouch", cls: "kind-badge k-vouch" },
    Challenge: { label: "challenge", cls: "kind-badge k-humanity" },
    SubmitVerdict: { label: "verdict", cls: "kind-badge k-humanity" },
    DeployContract: { label: "deploy", cls: "kind-badge k-deploy" },
    FundContract: { label: "fund", cls: "kind-badge k-invoke" },
    InvokeContract: { label: "invoke", cls: "kind-badge k-invoke" },
    SubmitEffect: { label: "effect", cls: "kind-badge k-invoke" },
    HumanitySystem: { label: "system", cls: "kind-badge k-system" },
    ContractHub: { label: "contract hub", cls: "kind-badge k-deploy" },
  };
  return map[kind] ?? { label: kind.toLowerCase(), cls: "kind-badge k-system" };
}

function hubCallCls(hub?: string): string {
  if (!hub) return "kind-badge k-system";
  if (hub.includes("Stream")) return "kind-badge k-stream";
  if (hub.includes("Humanity")) return "kind-badge k-humanity";
  if (hub.includes("Contract")) return "kind-badge k-deploy";
  return "kind-badge k-system";
}

function logCategoryClass(name: string | null): string {
  if (!name) return "log-name log-unknown";
  if (name.includes("Stream")) return "log-name log-stream";
  if (name.includes("Case") || name.includes("Verdict") || name.includes("Status") || name.includes("Registered")) return "log-name log-humanity";
  if (name.includes("Contract") || name.includes("Effect") || name.includes("Deployed")) return "log-name log-contract";
  if (name === "Transfer") return "log-name log-transfer";
  return "log-name log-unknown";
}

function Copy({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="copy"
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

// ---- Log entry renderer ---------------------------------------------------------------

function LogEntry({ log }: { log: DecodedLog }) {
  const name = log.name ?? "Unknown";
  const cls = logCategoryClass(log.name);
  const args = log.args ?? {};

  return (
    <div className="log-row">
      <span className={cls}>{name}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        {Object.keys(args).length > 0 ? (
          <div style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: "var(--muted)", wordBreak: "break-all" }}>
            {Object.entries(args).map(([k, v]) => (
              <span key={k} style={{ marginRight: ".75rem" }}>
                <span style={{ color: "var(--faint)" }}>{k}:</span>{" "}
                <span style={{ color: "var(--ink)" }}>{String(v)}</span>
              </span>
            ))}
          </div>
        ) : log.address ? (
          <span style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: "var(--faint)" }}>
            {shortAddr(log.address)}
          </span>
        ) : null}
      </div>
    </div>
  );
}

// ---- Transaction Detail Panel ---------------------------------------------------------

function TxDetail({ tx, onClose }: { tx: DecodedTransaction; onClose: () => void }) {
  const blockNum = parseBlockNum(tx.blockNumber);
  const feeHex = tx.fee ?? "0x0";
  const feeUbi = hexToUbi(feeHex, 6);
  const valueUbi = hexToUbi(tx.value ?? "0x0", 4);
  const nonce = parseInt(tx.nonce ?? "0x0", 16);

  return (
    <div className="card" style={{ marginBottom: "1.25rem" }}>
      <div className="row" style={{ marginBottom: "1rem" }}>
        <div>
          <div className="label" style={{ marginBottom: ".3rem" }}>Transaction</div>
          <div style={{ fontFamily: "var(--mono)", fontSize: ".78rem", color: "var(--muted)", wordBreak: "break-all" }}>
            {tx.hash}
          </div>
        </div>
        <div style={{ display: "flex", gap: ".5rem", flexShrink: 0 }}>
          <Copy value={tx.hash} />
          <button className="ghost" onClick={onClose} style={{ fontSize: ".75rem" }}>Back</button>
        </div>
      </div>

      {/* Core fields */}
      <dl className="kv" style={{ marginBottom: "1rem" }}>
        <dt>Block</dt>
        <dd>#{blockNum}</dd>
        <dt>From</dt>
        <dd style={{ wordBreak: "break-all" }}>
          {tx.from} <Copy value={tx.from} />
        </dd>
        <dt>To</dt>
        <dd style={{ wordBreak: "break-all" }}>{tx.to ?? "(contract create)"}</dd>
        <dt>Value</dt>
        <dd style={{ color: "var(--accent)" }}>{valueUbi}</dd>
        <dt>Nonce</dt>
        <dd>{nonce}</dd>
        <dt>Fee</dt>
        <dd style={{ color: "var(--warn)" }}>{feeUbi}</dd>
      </dl>

      {/* Decoded hub call */}
      {tx.call && (
        <div style={{ marginBottom: "1rem" }}>
          <div className="label" style={{ marginBottom: ".5rem" }}>Decoded call</div>
          <div style={{ background: "var(--glass-2)", border: "1px solid var(--line)", borderRadius: "10px", padding: ".75rem 1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: ".6rem", marginBottom: ".5rem" }}>
              {tx.call.hub && <span className={hubCallCls(tx.call.hub)}>{tx.call.hub}</span>}
              {tx.call.method && <span style={{ fontFamily: "var(--mono)", fontSize: ".8rem", color: "var(--ink)", fontWeight: 600 }}>{tx.call.method}</span>}
            </div>
            {tx.call.args && Object.keys(tx.call.args).length > 0 && (
              <div style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: "var(--muted)" }}>
                {Object.entries(tx.call.args).map(([k, v]) => (
                  <div key={k} style={{ marginBottom: ".2rem" }}>
                    <span style={{ color: "var(--faint)" }}>{k}:</span>{" "}
                    <span style={{ color: "var(--ink)", wordBreak: "break-all" }}>{String(v)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Decoded logs */}
      {tx.logs && tx.logs.length > 0 && (
        <div style={{ marginBottom: "1rem" }}>
          <div className="label" style={{ marginBottom: ".5rem" }}>Event logs ({tx.logs.length})</div>
          <div style={{ border: "1px solid var(--line)", borderRadius: "10px", padding: ".5rem .75rem" }}>
            {tx.logs.map((log, i) => (
              <LogEntry key={i} log={log} />
            ))}
          </div>
        </div>
      )}

      {/* Result / effect */}
      {tx.result && (
        <div>
          <div className="label" style={{ marginBottom: ".5rem" }}>Result</div>
          <div style={{ background: "rgba(79,231,168,.04)", border: "1px solid rgba(79,231,168,.18)", borderRadius: "10px", padding: ".75rem 1rem" }}>
            <div style={{ fontFamily: "var(--mono)", fontSize: ".75rem", color: "var(--muted)", wordBreak: "break-all" }}>
              {JSON.stringify(tx.result, null, 2)}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Block Detail Panel ---------------------------------------------------------------

function BlockDetail({ block, onClose, onSelectTx }: {
  block: DecodedBlock;
  onClose: () => void;
  onSelectTx: (hash: string) => void;
}) {
  const blockNum = parseBlockNum(block.number);
  const gasUsed = parseInt(block.gasUsed ?? "0x0", 16).toLocaleString();
  const baseFee = hexToUbi(block.baseFeePerGas ?? "0x0", 9);

  return (
    <div className="card" style={{ marginBottom: "1.25rem" }}>
      <div className="row" style={{ marginBottom: "1rem" }}>
        <div>
          <div className="label" style={{ marginBottom: ".3rem" }}>Block</div>
          <span style={{ fontFamily: "var(--mono)", fontSize: "1.1rem", fontWeight: 700, color: "var(--accent)" }}>
            #{blockNum}
          </span>
        </div>
        <button className="ghost" onClick={onClose} style={{ fontSize: ".75rem" }}>Back</button>
      </div>

      <dl className="kv" style={{ marginBottom: "1rem" }}>
        <dt>Hash</dt>
        <dd style={{ wordBreak: "break-all", fontSize: ".72rem" }}>
          {block.hash} <Copy value={block.hash} />
        </dd>
        <dt>Parent</dt>
        <dd style={{ wordBreak: "break-all", fontSize: ".72rem" }}>{shortHash(block.parentHash)}</dd>
        <dt>Timestamp</dt>
        <dd>{fmtTsLong(block.timestamp)}</dd>
        <dt>Miner</dt>
        <dd style={{ wordBreak: "break-all" }}>{block.miner ?? "—"}</dd>
        <dt>Gas used</dt>
        <dd>{gasUsed}</dd>
        <dt>Base fee</dt>
        <dd style={{ color: "var(--warn)" }}>{baseFee}</dd>
        <dt>State root</dt>
        <dd style={{ wordBreak: "break-all", fontSize: ".68rem", color: "var(--faint)" }}>{shortHash(block.stateRoot ?? "")}</dd>
        <dt>Txs root</dt>
        <dd style={{ wordBreak: "break-all", fontSize: ".68rem", color: "var(--faint)" }}>{shortHash(block.transactionsRoot ?? "")}</dd>
        <dt>Receipts root</dt>
        <dd style={{ wordBreak: "break-all", fontSize: ".68rem", color: "var(--faint)" }}>{shortHash(block.receiptsRoot ?? "")}</dd>
        <dt>Transactions</dt>
        <dd style={{ color: "var(--ink)" }}>{block.txCount ?? block.transactions?.length ?? 0}</dd>
      </dl>

      {/* Transaction list */}
      {block.transactions && block.transactions.length > 0 && (
        <div>
          <div className="label" style={{ marginBottom: ".5rem" }}>Transactions</div>
          <div style={{ border: "1px solid var(--line)", borderRadius: "10px", overflow: "hidden" }}>
            {block.transactions.map((tx, i) => {
              const call = tx.call;
              const hubLabel = call?.hub ?? call?.kind ?? "transfer";
              const methodLabel = call?.method ?? "";
              const badgeCls = hubCallCls(call?.hub);
              const feeUbi = hexToUbi(tx.fee ?? "0x0", 6);
              return (
                <div
                  key={tx.hash}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "7rem 1fr auto",
                    gap: ".6rem",
                    alignItems: "center",
                    padding: ".65rem .85rem",
                    borderTop: i === 0 ? "none" : "1px solid var(--line)",
                    cursor: "pointer",
                    transition: "background .12s",
                  }}
                  onClick={() => onSelectTx(tx.hash)}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--glass-2)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <span className={badgeCls}>{hubLabel}</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: "var(--muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {tx.hash}
                    </div>
                    <div style={{ fontSize: ".7rem", color: "var(--faint)", marginTop: ".1rem" }}>
                      {shortAddr(tx.from)} → {tx.to ? shortAddr(tx.to) : "(create)"}
                      {methodLabel && <span style={{ marginLeft: ".5rem", color: "var(--muted)" }}>· {methodLabel}</span>}
                    </div>
                  </div>
                  <span style={{ fontFamily: "var(--mono)", fontSize: ".7rem", color: "var(--faint)", textAlign: "right", whiteSpace: "nowrap" }}>
                    {feeUbi} fee
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {(!block.transactions || block.transactions.length === 0) && (
        <p className="muted small">No transactions in this block.</p>
      )}
    </div>
  );
}

// ---- Account View Panel ---------------------------------------------------------------

function AccountView({ address, onClose, onSelectTx }: {
  address: string;
  onClose: () => void;
  onSelectTx: (hash: string) => void;
}) {
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
        explorer.getAddressActivity(address, 40),
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
    <div className="card" style={{ marginBottom: "1.25rem" }}>
      <div className="row" style={{ marginBottom: ".85rem" }}>
        <div>
          <div className="label" style={{ marginBottom: ".3rem" }}>Account</div>
          <div style={{ fontFamily: "var(--mono)", fontSize: ".8rem", color: "var(--muted)", wordBreak: "break-all" }}>
            {address}
          </div>
        </div>
        <div style={{ display: "flex", gap: ".5rem" }}>
          <Copy value={address} />
          <button className="ghost" onClick={onClose} style={{ fontSize: ".75rem" }}>Back</button>
        </div>
      </div>

      {loading && !summary && <p className="muted small">Loading…</p>}
      {err && <p className="small" style={{ color: "var(--danger)" }}>{err}</p>}

      {summary && (
        <>
          <div className="acct-grid" style={{ marginBottom: "1rem" }}>
            <div className="acct-stat">
              <div className="label">Balance</div>
              <div className="acct-val" style={{ color: "var(--accent)" }}>{hexToUbi(summary.balance)}</div>
            </div>
            <div className="acct-stat">
              <div className="label">Nonce</div>
              <div className="acct-val">{parseInt(summary.nonce, 16)}</div>
            </div>
            <div className="acct-stat">
              <div className="label">Identity</div>
              <div className="acct-val">
                {summary.human_status ? (
                  <span className={humanStatusCls}>{summary.human_status}</span>
                ) : (
                  <span className="muted small">—</span>
                )}
              </div>
            </div>
            <div className="acct-stat">
              <div className="label">Streams in / out</div>
              <div className="acct-val">{summary.streams_in} / {summary.streams_out}</div>
            </div>
            <div className="acct-stat">
              <div className="label">Contracts</div>
              <div className="acct-val" style={{ color: "var(--accent-2)" }}>{summary.contracts}</div>
            </div>
            <div className="acct-stat">
              <div className="label">Tx count</div>
              <div className="acct-val">{summary.tx_count}</div>
            </div>
          </div>

          {/* Activity feed */}
          <div className="label" style={{ marginBottom: ".5rem" }}>
            Recent activity ({activity.length})
          </div>
          {activity.length === 0 ? (
            <p className="muted small">No activity yet.</p>
          ) : (
            <div style={{ border: "1px solid var(--line)", borderRadius: "10px", overflow: "hidden" }}>
              {activity.map((row, i) => {
                const badge = kindBadge(row.kind);
                const blockNum = parseBlockNum(row.blockNumber);
                const feeUbi = row.fee ? hexToUbi(row.fee, 6) : null;
                return (
                  <div
                    key={`${row.hash}-${i}`}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "6.5rem 5rem 1fr auto",
                      gap: ".5rem",
                      alignItems: "center",
                      padding: ".55rem .85rem",
                      borderTop: i === 0 ? "none" : "1px solid var(--line)",
                      cursor: "pointer",
                      transition: "background .12s",
                    }}
                    onClick={() => onSelectTx(row.hash)}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--glass-2)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    <span className={badge.cls}>{badge.label}</span>
                    <span className="block-num">#{blockNum}</span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: "var(--muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {shortHash(row.hash)}
                      {row.counterparty && (
                        <span style={{ color: "var(--faint)", marginLeft: ".4rem" }}>· {shortAddr(row.counterparty)}</span>
                      )}
                    </span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: ".7rem", color: "var(--faint)", textAlign: "right", whiteSpace: "nowrap" }}>
                      {feeUbi ?? (row.value !== "0x0" && row.value !== "0x00" ? hexToUbi(row.value, 4) : "")}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ---- Main Explorer Component ----------------------------------------------------------

type View =
  | { kind: "list" }
  | { kind: "block"; block: DecodedBlock }
  | { kind: "tx"; tx: DecodedTransaction }
  | { kind: "account"; address: string };

export function Explorer() {
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [latest, setLatest] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState<string | null>(null);
  const [view, setView] = useState<View>({ kind: "list" });

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

  const goBack = useCallback(() => {
    setView({ kind: "list" });
    setSearchErr(null);
  }, []);

  const openTx = useCallback(async (hash: string) => {
    setSearching(true);
    setSearchErr(null);
    try {
      const tx = await explorer.getDecodedTransaction(hash);
      if (tx) {
        setView({ kind: "tx", tx });
      } else {
        setSearchErr("Transaction not found.");
      }
    } catch (e) {
      setSearchErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSearching(false);
    }
  }, []);

  const openBlock = useCallback(async (numOrHash: string | number) => {
    setSearching(true);
    setSearchErr(null);
    try {
      const tag = typeof numOrHash === "number"
        ? `0x${numOrHash.toString(16)}`
        : /^\d+$/.test(String(numOrHash))
          ? `0x${parseInt(String(numOrHash), 10).toString(16)}`
          : String(numOrHash);
      const block = await explorer.getBlock(tag);
      if (block) {
        setView({ kind: "block", block });
      } else {
        setSearchErr("Block not found.");
      }
    } catch (e) {
      setSearchErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSearching(false);
    }
  }, []);

  const search = useCallback(async () => {
    const q = query.trim();
    if (!q) return;
    setSearchErr(null);

    if (/^0x[0-9a-fA-F]{64}$/.test(q)) {
      // 66-char hex = tx hash
      await openTx(q);
    } else if (/^0x[0-9a-fA-F]{40}$/.test(q)) {
      // 42-char = address
      setView({ kind: "account", address: q });
    } else if (/^\d+$/.test(q)) {
      // decimal block number
      await openBlock(parseInt(q, 10));
    } else if (/^0x[0-9a-fA-F]{1,}$/.test(q) && q.length <= 18) {
      // hex block number
      await openBlock(q);
    } else {
      setSearchErr("Enter: address (0x…40), tx hash (0x…64), or block number.");
    }
  }, [query, openTx, openBlock]);

  return (
    <div>
      {/* Search bar */}
      <div className="card">
        <div className="card-header">
          <h3>Deep Explorer</h3>
          {latest != null && (
            <span
              className="block-num"
              style={{ cursor: "pointer" }}
              onClick={() => openBlock(latest)}
              title="Open latest block"
            >
              #{latest}
            </span>
          )}
        </div>
        <div className="expl-search">
          <input
            placeholder="Address (0x…40) · tx hash (0x…64) · block number"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
            spellCheck={false}
            autoComplete="off"
          />
          <button
            className="primary"
            onClick={search}
            disabled={searching}
            style={{ whiteSpace: "nowrap" }}
          >
            {searching ? "…" : "Search"}
          </button>
        </div>
        {searchErr && (
          <p className="small" style={{ color: "var(--danger)", marginTop: ".5rem" }}>
            {searchErr}
          </p>
        )}
      </div>

      {/* Drill-down views */}
      {view.kind === "block" && (
        <BlockDetail
          block={view.block}
          onClose={goBack}
          onSelectTx={openTx}
        />
      )}

      {view.kind === "tx" && (
        <TxDetail
          tx={view.tx}
          onClose={goBack}
        />
      )}

      {view.kind === "account" && (
        <AccountView
          address={view.address}
          onClose={goBack}
          onSelectTx={openTx}
        />
      )}

      {/* Latest blocks list */}
      <div className="card">
        <div className="card-header">
          <h3>Latest blocks</h3>
          <span className="tag green">live</span>
        </div>
        {blocks.length === 0 ? (
          <p className="muted small">No blocks yet — is the node running?</p>
        ) : (
          <div className="block-list">
            {blocks.map((b, i) => {
              const num = parseInt(b.number, 16);
              const txCount = Array.isArray(b.transactions) ? b.transactions.length : 0;
              return (
                <div
                  className="block-row"
                  key={b.hash || b.number}
                  style={{ cursor: "pointer", transition: "background .12s", borderRadius: "8px", padding: ".6rem .5rem" }}
                  onClick={() => openBlock(num)}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--glass-2)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <span className="block-num">#{num}</span>
                  <span className="block-hash">{shortHash(b.hash)}</span>
                  <span className="muted small">
                    {txCount} tx{txCount !== 1 ? "s" : ""}
                  </span>
                  <span className="block-ts">{fmtTs(b.timestamp)}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
