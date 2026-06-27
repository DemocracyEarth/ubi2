"use client";

/**
 * Shared explorer detail panel components.
 * Used by both the in-page Explorer (apps/wallet/app/explorer.tsx)
 * and the standalone URL routes (/tx/[hash], /block/[id], /address/[addr]).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  ExplorerReader,
  formatUbi,
  type AccountSummary,
  type ActivityRow,
  type DecodedBlock,
  type DecodedTransaction,
  type DecodedLog,
} from "@ubi2/sdk";
import { RPC_URL } from "./config";

// Lazily created singletons (safe — only runs client-side)
let _client: Ubi2Client | null = null;
let _explorer: ExplorerReader | null = null;

export function getClient(): Ubi2Client {
  if (!_client) _client = new Ubi2Client({ url: RPC_URL });
  return _client;
}

export function getExplorer(): ExplorerReader {
  if (!_explorer) _explorer = new ExplorerReader(getClient());
  return _explorer;
}

const POLL_MS = 4000;

// ---- Helpers -----------------------------------------------------------------------

export function shortHash(h: string): string {
  if (!h || h.length < 14) return h;
  return `${h.slice(0, 8)}…${h.slice(-6)}`;
}

export function shortAddr(a: string): string {
  if (!a || a.length < 12) return a;
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

export function fmtTs(hexSecs: string): string {
  const secs = parseInt(hexSecs, 16);
  if (!Number.isFinite(secs)) return "—";
  const d = new Date(secs * 1000);
  return d.toLocaleTimeString();
}

export function fmtTsLong(hexSecs: string): string {
  const secs = parseInt(hexSecs, 16);
  if (!Number.isFinite(secs)) return "—";
  return new Date(secs * 1000).toLocaleString();
}

export function hexToUbi(hex: string, frac = 4): string {
  try {
    return formatUbi(BigInt(hex), frac);
  } catch {
    return "0 UBI";
  }
}

export function parseBlockNum(s: string): number {
  if (s.startsWith("0x")) return parseInt(s, 16);
  return parseInt(s, 10);
}

export function kindBadge(kind: string): { label: string; cls: string } {
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

export function hubCallCls(hub?: string): string {
  if (!hub) return "kind-badge k-system";
  if (hub.includes("Stream")) return "kind-badge k-stream";
  if (hub.includes("Humanity")) return "kind-badge k-humanity";
  if (hub.includes("Contract")) return "kind-badge k-deploy";
  return "kind-badge k-system";
}

export function logCategoryClass(name: string | null): string {
  if (!name) return "log-name log-unknown";
  if (name.includes("Stream")) return "log-name log-stream";
  if (
    name.includes("Case") ||
    name.includes("Verdict") ||
    name.includes("Status") ||
    name.includes("Registered")
  )
    return "log-name log-humanity";
  if (
    name.includes("Contract") ||
    name.includes("Effect") ||
    name.includes("Deployed")
  )
    return "log-name log-contract";
  if (name === "Transfer") return "log-name log-transfer";
  return "log-name log-unknown";
}

// ---- Copy button -------------------------------------------------------------------

export function Copy({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="copy"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* unavailable */
        }
      }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

// ---- Log entry renderer ------------------------------------------------------------

function LogEntry({ log }: { log: DecodedLog }) {
  const name = log.name ?? "Unknown";
  const cls = logCategoryClass(log.name);
  const args = log.args ?? {};

  return (
    <div className="log-row">
      <span className={cls}>{name}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        {Object.keys(args).length > 0 ? (
          <div
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".72rem",
              color: "var(--muted)",
              wordBreak: "break-all",
            }}
          >
            {Object.entries(args).map(([k, v]) => (
              <span key={k} style={{ marginRight: ".75rem" }}>
                <span style={{ color: "var(--faint)" }}>{k}:</span>{" "}
                <span style={{ color: "var(--ink)" }}>{String(v)}</span>
              </span>
            ))}
          </div>
        ) : log.address ? (
          <span
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".72rem",
              color: "var(--faint)",
            }}
          >
            {shortAddr(log.address)}
          </span>
        ) : null}
      </div>
    </div>
  );
}

// ---- Transaction Detail Panel ------------------------------------------------------

export function TxDetail({
  tx,
  onClose,
  onSelectBlock,
  onSelectAddress,
}: {
  tx: DecodedTransaction;
  onClose?: () => void;
  onSelectBlock?: (blockNum: number) => void;
  onSelectAddress?: (addr: string) => void;
}) {
  const blockNum = parseBlockNum(tx.blockNumber);
  const feeHex = tx.fee ?? "0x0";
  const feeUbi = hexToUbi(feeHex, 6);
  const valueUbi = hexToUbi(tx.value ?? "0x0", 4);
  const nonce = parseInt(tx.nonce ?? "0x0", 16);

  return (
    <div className="card" style={{ marginBottom: "1.25rem" }}>
      <div className="row" style={{ marginBottom: "1rem" }}>
        <div>
          <div className="label" style={{ marginBottom: ".3rem" }}>
            Transaction
          </div>
          <div
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".78rem",
              color: "var(--muted)",
              wordBreak: "break-all",
            }}
          >
            {tx.hash}
          </div>
        </div>
        <div style={{ display: "flex", gap: ".5rem", flexShrink: 0 }}>
          <Copy value={tx.hash} />
          {onClose && (
            <button
              className="ghost"
              onClick={onClose}
              style={{ fontSize: ".75rem" }}
            >
              Back
            </button>
          )}
        </div>
      </div>

      {/* Core fields */}
      <dl className="kv" style={{ marginBottom: "1rem" }}>
        <dt>Block</dt>
        <dd>
          {onSelectBlock ? (
            <button
              className="ghost"
              style={{ fontSize: ".82rem", padding: "2px 6px" }}
              onClick={() => onSelectBlock(blockNum)}
            >
              #{blockNum}
            </button>
          ) : (
            <a href={`/block/${blockNum}`} style={{ color: "var(--accent)" }}>
              #{blockNum}
            </a>
          )}
        </dd>
        <dt>From</dt>
        <dd style={{ wordBreak: "break-all" }}>
          {onSelectAddress ? (
            <button
              className="ghost"
              style={{
                fontSize: ".78rem",
                padding: "2px 4px",
                fontFamily: "var(--mono)",
              }}
              onClick={() => onSelectAddress(tx.from)}
            >
              {tx.from}
            </button>
          ) : (
            <a
              href={`/address/${tx.from}`}
              style={{
                color: "var(--accent)",
                fontFamily: "var(--mono)",
                fontSize: ".78rem",
              }}
            >
              {tx.from}
            </a>
          )}{" "}
          <Copy value={tx.from} />
        </dd>
        <dt>To</dt>
        <dd style={{ wordBreak: "break-all" }}>
          {tx.to ? (
            onSelectAddress ? (
              <button
                className="ghost"
                style={{
                  fontSize: ".78rem",
                  padding: "2px 4px",
                  fontFamily: "var(--mono)",
                }}
                onClick={() => onSelectAddress(tx.to!)}
              >
                {tx.to}
              </button>
            ) : (
              <a
                href={`/address/${tx.to}`}
                style={{
                  color: "var(--accent)",
                  fontFamily: "var(--mono)",
                  fontSize: ".78rem",
                }}
              >
                {tx.to}
              </a>
            )
          ) : (
            "(contract create)"
          )}
        </dd>
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
          <div className="label" style={{ marginBottom: ".5rem" }}>
            Decoded call
          </div>
          <div
            style={{
              background: "var(--glass-2)",
              border: "1px solid var(--line)",
              borderRadius: "10px",
              padding: ".75rem 1rem",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: ".6rem",
                marginBottom: ".5rem",
              }}
            >
              {tx.call.hub && (
                <span className={hubCallCls(tx.call.hub)}>{tx.call.hub}</span>
              )}
              {tx.call.method && (
                <span
                  style={{
                    fontFamily: "var(--mono)",
                    fontSize: ".8rem",
                    color: "var(--ink)",
                    fontWeight: 600,
                  }}
                >
                  {tx.call.method}
                </span>
              )}
            </div>
            {tx.call.args && Object.keys(tx.call.args).length > 0 && (
              <div
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: ".72rem",
                  color: "var(--muted)",
                }}
              >
                {Object.entries(tx.call.args).map(([k, v]) => (
                  <div key={k} style={{ marginBottom: ".2rem" }}>
                    <span style={{ color: "var(--faint)" }}>{k}:</span>{" "}
                    <span style={{ color: "var(--ink)", wordBreak: "break-all" }}>
                      {String(v)}
                    </span>
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
          <div className="label" style={{ marginBottom: ".5rem" }}>
            Event logs ({tx.logs.length})
          </div>
          <div
            style={{
              border: "1px solid var(--line)",
              borderRadius: "10px",
              padding: ".5rem .75rem",
            }}
          >
            {tx.logs.map((log, i) => (
              <LogEntry key={i} log={log} />
            ))}
          </div>
        </div>
      )}

      {/* Result / effect */}
      {tx.result && (
        <div>
          <div className="label" style={{ marginBottom: ".5rem" }}>
            Result
          </div>
          <div
            style={{
              background: "rgba(79,231,168,.04)",
              border: "1px solid rgba(79,231,168,.18)",
              borderRadius: "10px",
              padding: ".75rem 1rem",
            }}
          >
            <div
              style={{
                fontFamily: "var(--mono)",
                fontSize: ".75rem",
                color: "var(--muted)",
                wordBreak: "break-all",
              }}
            >
              {JSON.stringify(tx.result, null, 2)}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Block Detail Panel ------------------------------------------------------------

export function BlockDetail({
  block,
  onClose,
  onSelectTx,
  onSelectAddress,
}: {
  block: DecodedBlock;
  onClose?: () => void;
  onSelectTx?: (hash: string) => void;
  onSelectAddress?: (addr: string) => void;
}) {
  const blockNum = parseBlockNum(block.number);
  const gasUsed = parseInt(block.gasUsed ?? "0x0", 16).toLocaleString();
  const baseFee = hexToUbi(block.baseFeePerGas ?? "0x0", 9);

  return (
    <div className="card" style={{ marginBottom: "1.25rem" }}>
      <div className="row" style={{ marginBottom: "1rem" }}>
        <div>
          <div className="label" style={{ marginBottom: ".3rem" }}>
            Block
          </div>
          <span
            style={{
              fontFamily: "var(--mono)",
              fontSize: "1.1rem",
              fontWeight: 700,
              color: "var(--accent)",
            }}
          >
            #{blockNum}
          </span>
        </div>
        {onClose && (
          <button
            className="ghost"
            onClick={onClose}
            style={{ fontSize: ".75rem" }}
          >
            Back
          </button>
        )}
      </div>

      <dl className="kv" style={{ marginBottom: "1rem" }}>
        <dt>Hash</dt>
        <dd style={{ wordBreak: "break-all", fontSize: ".72rem" }}>
          {block.hash} <Copy value={block.hash} />
        </dd>
        <dt>Parent</dt>
        <dd style={{ wordBreak: "break-all", fontSize: ".72rem" }}>
          {shortHash(block.parentHash)}
        </dd>
        <dt>Timestamp</dt>
        <dd>{fmtTsLong(block.timestamp)}</dd>
        <dt>Miner</dt>
        <dd style={{ wordBreak: "break-all" }}>
          {block.miner ? (
            onSelectAddress ? (
              <button
                className="ghost"
                style={{ fontSize: ".78rem", fontFamily: "var(--mono)" }}
                onClick={() => onSelectAddress(block.miner)}
              >
                {block.miner}
              </button>
            ) : (
              <a
                href={`/address/${block.miner}`}
                style={{ color: "var(--accent)", fontFamily: "var(--mono)", fontSize: ".78rem" }}
              >
                {block.miner}
              </a>
            )
          ) : (
            "—"
          )}
        </dd>
        <dt>Gas used</dt>
        <dd>{gasUsed}</dd>
        <dt>Base fee</dt>
        <dd style={{ color: "var(--warn)" }}>{baseFee}</dd>
        <dt>State root</dt>
        <dd
          style={{
            wordBreak: "break-all",
            fontSize: ".68rem",
            color: "var(--faint)",
          }}
        >
          {shortHash(block.stateRoot ?? "")}
        </dd>
        <dt>Txs root</dt>
        <dd
          style={{
            wordBreak: "break-all",
            fontSize: ".68rem",
            color: "var(--faint)",
          }}
        >
          {shortHash(block.transactionsRoot ?? "")}
        </dd>
        <dt>Receipts root</dt>
        <dd
          style={{
            wordBreak: "break-all",
            fontSize: ".68rem",
            color: "var(--faint)",
          }}
        >
          {shortHash(block.receiptsRoot ?? "")}
        </dd>
        <dt>Transactions</dt>
        <dd style={{ color: "var(--ink)" }}>
          {block.txCount ?? block.transactions?.length ?? 0}
        </dd>
      </dl>

      {/* Transaction list */}
      {block.transactions && block.transactions.length > 0 && (
        <div>
          <div className="label" style={{ marginBottom: ".5rem" }}>
            Transactions
          </div>
          <div
            style={{
              border: "1px solid var(--line)",
              borderRadius: "10px",
              overflow: "hidden",
            }}
          >
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
                  onClick={() =>
                    onSelectTx
                      ? onSelectTx(tx.hash)
                      : (window.location.href = `/tx/${tx.hash}`)
                  }
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background = "var(--glass-2)")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = "transparent")
                  }
                >
                  <span className={badgeCls}>{hubLabel}</span>
                  <div style={{ minWidth: 0 }}>
                    <div
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: ".72rem",
                        color: "var(--muted)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {tx.hash}
                    </div>
                    <div
                      style={{
                        fontSize: ".7rem",
                        color: "var(--faint)",
                        marginTop: ".1rem",
                      }}
                    >
                      {shortAddr(tx.from)} → {tx.to ? shortAddr(tx.to) : "(create)"}
                      {methodLabel && (
                        <span style={{ marginLeft: ".5rem", color: "var(--muted)" }}>
                          · {methodLabel}
                        </span>
                      )}
                    </div>
                  </div>
                  <span
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: ".7rem",
                      color: "var(--faint)",
                      textAlign: "right",
                      whiteSpace: "nowrap",
                    }}
                  >
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

// ---- Account View Panel ------------------------------------------------------------

export function AccountView({
  address,
  onClose,
  onSelectTx,
}: {
  address: string;
  onClose?: () => void;
  onSelectTx?: (hash: string) => void;
}) {
  const [summary, setSummary] = useState<AccountSummary | null>(null);
  const [activity, setActivity] = useState<ActivityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const explorer = getExplorer();
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
          <div className="label" style={{ marginBottom: ".3rem" }}>
            Account
          </div>
          <div
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".8rem",
              color: "var(--muted)",
              wordBreak: "break-all",
            }}
          >
            {address}
          </div>
        </div>
        <div style={{ display: "flex", gap: ".5rem" }}>
          <Copy value={address} />
          {onClose && (
            <button
              className="ghost"
              onClick={onClose}
              style={{ fontSize: ".75rem" }}
            >
              Back
            </button>
          )}
        </div>
      </div>

      {loading && !summary && <p className="muted small">Loading…</p>}
      {err && (
        <p className="small" style={{ color: "var(--danger)" }}>
          {err}
        </p>
      )}

      {summary && (
        <>
          <div className="acct-grid" style={{ marginBottom: "1rem" }}>
            <div className="acct-stat">
              <div className="label">Balance</div>
              <div className="acct-val" style={{ color: "var(--accent)" }}>
                {hexToUbi(summary.balance)}
              </div>
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
              <div className="acct-val">
                {summary.streams_in} / {summary.streams_out}
              </div>
            </div>
            <div className="acct-stat">
              <div className="label">Contracts</div>
              <div
                className="acct-val"
                style={{ color: "var(--accent-2)" }}
              >
                {summary.contracts}
              </div>
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
            <div
              style={{
                border: "1px solid var(--line)",
                borderRadius: "10px",
                overflow: "hidden",
              }}
            >
              {activity.map((row, i) => {
                const badge = kindBadge(row.kind);
                const blockN = parseBlockNum(row.blockNumber);
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
                    onClick={() =>
                      onSelectTx
                        ? onSelectTx(row.hash)
                        : (window.location.href = `/tx/${row.hash}`)
                    }
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.background = "var(--glass-2)")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.background = "transparent")
                    }
                  >
                    <span className={badge.cls}>{badge.label}</span>
                    <span className="block-num">#{blockN}</span>
                    <span
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: ".72rem",
                        color: "var(--muted)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {shortHash(row.hash)}
                      {row.counterparty && (
                        <span
                          style={{
                            color: "var(--faint)",
                            marginLeft: ".4rem",
                          }}
                        >
                          · {shortAddr(row.counterparty)}
                        </span>
                      )}
                    </span>
                    <span
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: ".7rem",
                        color: "var(--faint)",
                        textAlign: "right",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {feeUbi ??
                        (row.value !== "0x0" && row.value !== "0x00"
                          ? hexToUbi(row.value, 4)
                          : "")}
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

// ---- Page-level loader components --------------------------------------------------
// Used by the standalone route pages to fetch and render in SSR-safe way.

type TxPageState =
  | { status: "loading" }
  | { status: "found"; tx: DecodedTransaction }
  | { status: "not_found"; hash: string }
  | { status: "error"; message: string };

export function TxPageContent({
  hash,
  onSelectBlock,
  onSelectAddress,
}: {
  hash: string;
  onSelectBlock?: (n: number) => void;
  onSelectAddress?: (addr: string) => void;
}) {
  const [state, setState] = useState<TxPageState>({ status: "loading" });
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    setState({ status: "loading" });
    const explorer = getExplorer();
    explorer
      .getDecodedTransaction(hash)
      .then((tx) => {
        if (!mountedRef.current) return;
        if (tx) {
          setState({ status: "found", tx });
        } else {
          setState({ status: "not_found", hash });
        }
      })
      .catch((e) => {
        if (!mountedRef.current) return;
        setState({
          status: "error",
          message: e instanceof Error ? e.message : String(e),
        });
      });
  }, [hash]);

  if (state.status === "loading") {
    return (
      <div className="card">
        <p className="muted small">Looking up transaction…</p>
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div className="card">
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: ".75rem",
          }}
        >
          <div className="label" style={{ color: "var(--danger)" }}>
            RPC error
          </div>
          <p className="small" style={{ color: "var(--muted)", margin: 0 }}>
            {state.message}
          </p>
          <p className="small muted" style={{ margin: 0 }}>
            The node may be down or the transaction hash may be malformed.
          </p>
        </div>
      </div>
    );
  }

  if (state.status === "not_found") {
    return (
      <div className="card">
        <div
          style={{ display: "flex", flexDirection: "column", gap: ".85rem" }}
        >
          <div className="label" style={{ color: "var(--warn)" }}>
            Transaction not found
          </div>
          <div
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".78rem",
              color: "var(--muted)",
              wordBreak: "break-all",
            }}
          >
            {state.hash}
          </div>
          <p
            className="small"
            style={{ color: "var(--muted)", margin: 0, lineHeight: 1.6 }}
          >
            This transaction was <strong>rejected before being included</strong>{" "}
            in a block — it has no on-chain record. It was never mined and no
            state was changed.
          </p>
          <div
            style={{
              background: "rgba(251,191,92,.05)",
              border: "1px solid rgba(251,191,92,.2)",
              borderRadius: "10px",
              padding: ".75rem 1rem",
            }}
          >
            <div
              className="label"
              style={{ marginBottom: ".5rem", color: "var(--warn)" }}
            >
              Common reasons a transaction is not found
            </div>
            <ul
              style={{
                margin: 0,
                paddingLeft: "1.25rem",
                color: "var(--muted)",
                fontSize: ".82rem",
                lineHeight: 1.7,
              }}
            >
              <li>
                <strong>Wrong nonce</strong> — a gap or replay caused the node
                to reject it at submission.
              </li>
              <li>
                <strong>Insufficient balance</strong> — the sender did not have
                enough UBI to cover value + fee.
              </li>
              <li>
                <strong>Gas price too low</strong> — the base fee on this chain
                requires a higher{" "}
                <span style={{ fontFamily: "var(--mono)" }}>maxFeePerGas</span>.
              </li>
              <li>
                <strong>Invalid signature</strong> — wrong chain ID or a
                corrupted envelope.
              </li>
              <li>
                <strong>Stale hash</strong> — the link was generated against a
                different devnet state that was since reset.
              </li>
            </ul>
          </div>
          <p className="small muted" style={{ margin: 0 }}>
            If you sent UBI and it was not received, your balance has not
            changed — the funds are still in your account.
          </p>
        </div>
      </div>
    );
  }

  return (
    <TxDetail
      tx={state.tx}
      onSelectBlock={onSelectBlock}
      onSelectAddress={onSelectAddress}
    />
  );
}

type BlockPageState =
  | { status: "loading" }
  | { status: "found"; block: DecodedBlock }
  | { status: "not_found"; id: string }
  | { status: "error"; message: string };

export function BlockPageContent({
  id,
  onSelectTx,
  onSelectAddress,
}: {
  id: string;
  onSelectTx?: (hash: string) => void;
  onSelectAddress?: (addr: string) => void;
}) {
  const [state, setState] = useState<BlockPageState>({ status: "loading" });
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    setState({ status: "loading" });
    const explorer = getExplorer();
    // Support decimal numbers, hex numbers, "latest", and block hashes
    const tag =
      /^\d+$/.test(id)
        ? `0x${parseInt(id, 10).toString(16)}`
        : id.startsWith("0x") && id.length <= 18
          ? id
          : id; // "latest", "earliest", or 32-byte hash
    explorer
      .getBlock(tag)
      .then((block) => {
        if (!mountedRef.current) return;
        if (block) {
          setState({ status: "found", block });
        } else {
          setState({ status: "not_found", id });
        }
      })
      .catch((e) => {
        if (!mountedRef.current) return;
        setState({
          status: "error",
          message: e instanceof Error ? e.message : String(e),
        });
      });
  }, [id]);

  if (state.status === "loading") {
    return (
      <div className="card">
        <p className="muted small">Looking up block…</p>
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div className="card">
        <div className="label" style={{ color: "var(--danger)" }}>
          RPC error
        </div>
        <p className="small muted">{state.message}</p>
      </div>
    );
  }

  if (state.status === "not_found") {
    return (
      <div className="card">
        <div className="label" style={{ color: "var(--warn)" }}>
          Block not found
        </div>
        <p
          className="small"
          style={{ color: "var(--muted)", marginTop: ".5rem" }}
        >
          Block <span style={{ fontFamily: "var(--mono)" }}>{state.id}</span>{" "}
          does not exist on this chain. The chain may not have reached this
          block height yet, or the hash does not match any known block.
        </p>
      </div>
    );
  }

  return (
    <BlockDetail
      block={state.block}
      onSelectTx={onSelectTx}
      onSelectAddress={onSelectAddress}
    />
  );
}

type AddressPageState =
  | { status: "loading" }
  | { status: "found" }
  | { status: "error"; message: string };

export function AddressPageContent({
  address,
  onSelectTx,
}: {
  address: string;
  onSelectTx?: (hash: string) => void;
}) {
  const [state, setState] = useState<AddressPageState>({ status: "loading" });

  useEffect(() => {
    // AccountView loads itself; we just need to confirm the address looks valid
    if (/^0x[0-9a-fA-F]{40}$/.test(address)) {
      setState({ status: "found" });
    } else {
      setState({ status: "error", message: `"${address}" is not a valid EVM address.` });
    }
  }, [address]);

  if (state.status === "loading") {
    return (
      <div className="card">
        <p className="muted small">Loading…</p>
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div className="card">
        <div className="label" style={{ color: "var(--danger)" }}>
          Invalid address
        </div>
        <p className="small muted" style={{ marginTop: ".5rem" }}>
          {state.message}
        </p>
      </div>
    );
  }

  return <AccountView address={address} onSelectTx={onSelectTx} />;
}
