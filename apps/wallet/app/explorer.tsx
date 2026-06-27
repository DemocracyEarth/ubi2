"use client";

/**
 * Deep block explorer — obsidian-glass, cycle-5.
 * Search by address / tx hash / block number.
 * Block page: full header fields + decoded tx list (ubi_getBlock).
 * Tx page: from/to/fee, decoded hub call, decoded logs, result (ubi_getTransaction).
 * Account page: ubi_getAccount + ubi_getAddressActivity.
 * Latest blocks list polling every 4 s.
 *
 * Improvement (field-test): Non-empty blocks toggle (default ON) via ubi_getRecentBlocks.
 * Improvement (field-test): Contracts directory via ubi_getContracts with contract badge.
 *
 * Detail views are also available as URL-addressable routes:
 *   /tx/[hash], /block/[id], /address/[addr], /account/[addr]
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  ExplorerReader,
  formatUbi,
  type DecodedTransaction,
  type DecodedBlock,
  type BlockSummary,
  type ContractSummary,
} from "@ubi2/sdk";
import { RPC_URL } from "./config";
import {
  TxDetail,
  BlockDetail,
  AccountView,
  shortHash,
  fmtTs,
  getExplorer,
} from "./explorer-components";

const client = new Ubi2Client({ url: RPC_URL });
const explorerReader = new ExplorerReader(client);

const POLL_MS = 4000;

// ---- Helpers -----------------------------------------------------------------------

function hexToUbi(hex: string, frac = 4): string {
  try { return formatUbi(BigInt(hex), frac); } catch { return "0 UBI"; }
}

function short(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function fmtUnixTs(secs: number): string {
  if (!Number.isFinite(secs) || secs === 0) return "—";
  return new Date(secs * 1000).toLocaleTimeString();
}

// ---- Contract badge — marks an address as a known contract -------------------------

function ContractBadge() {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.25rem",
        fontSize: "0.6rem",
        fontWeight: 700,
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        color: "var(--accent-2)",
        background: "rgba(139,123,255,.12)",
        border: "1px solid rgba(139,123,255,.28)",
        borderRadius: "5px",
        padding: "1px 5px",
        verticalAlign: "middle",
        marginLeft: "0.35rem",
      }}
    >
      contract
    </span>
  );
}

// ---- Main Explorer Component ----------------------------------------------------------

type ExplorerTab = "blocks" | "contracts";

type View =
  | { kind: "list" }
  | { kind: "block"; block: DecodedBlock }
  | { kind: "tx"; tx: DecodedTransaction }
  | { kind: "account"; address: string }
  | { kind: "contract"; contractId: number };

interface ExplorerProps {
  /** Deep-link: open this block number on mount (consumed once). */
  initialBlockTarget?: number | null;
  /** Deep-link: open this tx hash on mount (consumed once). */
  initialTxTarget?: string | null;
  /** Called after the initial target has been consumed so the parent can clear it. */
  onConsumeTarget?: () => void;
}

export function Explorer({ initialBlockTarget, initialTxTarget, onConsumeTarget }: ExplorerProps = {}) {
  const [activeTab, setActiveTab] = useState<ExplorerTab>("blocks");

  // Block list state
  const [blocks, setBlocks] = useState<BlockSummary[]>([]);
  const [nonEmptyOnly, setNonEmptyOnly] = useState(true);
  const [latest, setLatest] = useState<number | null>(null);
  const [blocksLoading, setBlocksLoading] = useState(false);

  // Contract directory state
  const [contracts, setContracts] = useState<ContractSummary[]>([]);
  const [contractsLoading, setContractsLoading] = useState(false);

  // Search + detail state
  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState<string | null>(null);
  const [view, setView] = useState<View>({ kind: "list" });

  const pollRef = useRef<() => void>(() => {});

  // Fetch blocks using the new ubi_getRecentBlocks RPC
  const refreshBlocks = useCallback(async (nonEmpty: boolean) => {
    setBlocksLoading(true);
    try {
      const [head, summaries] = await Promise.all([
        client.blockNumber(),
        explorerReader.getRecentBlocks(20, nonEmpty),
      ]);
      setLatest(head);
      setBlocks(summaries);
    } catch {
      // Fall back to eth_getBlockByNumber if the new RPC is unavailable
      try {
        const head = await client.blockNumber();
        setLatest(head);
        const start = Math.max(0, head - 19);
        const nums: number[] = [];
        for (let n = head; n >= start; n--) nums.push(n);
        const fetched = await Promise.all(nums.map((n) => client.getBlockByNumber(n)));
        const summaries: BlockSummary[] = fetched
          .filter((b): b is NonNullable<typeof b> => b != null)
          .map((b) => ({
            number: b.number,
            hash: b.hash,
            parentHash: b.parentHash,
            timestamp: b.timestamp,
            txCount: Array.isArray(b.transactions) ? b.transactions.length : 0,
            gasUsed: b.gasUsed,
            miner: b.miner,
          }))
          .filter((b) => !nonEmpty || b.txCount > 0);
        setBlocks(summaries);
      } catch {
        /* node may be down */
      }
    } finally {
      setBlocksLoading(false);
    }
  }, []);

  const refreshContracts = useCallback(async () => {
    setContractsLoading(true);
    try {
      const cs = await explorerReader.getContracts(50);
      setContracts(cs);
    } catch {
      /* node may not support this RPC yet */
      setContracts([]);
    } finally {
      setContractsLoading(false);
    }
  }, []);

  const refresh = useCallback(() => {
    refreshBlocks(nonEmptyOnly);
    refreshContracts();
  }, [nonEmptyOnly, refreshBlocks, refreshContracts]);

  pollRef.current = refresh;

  useEffect(() => {
    refresh();
    const id = setInterval(() => pollRef.current(), POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  // Re-fetch blocks when the toggle changes
  useEffect(() => {
    refreshBlocks(nonEmptyOnly);
  }, [nonEmptyOnly, refreshBlocks]);

  const goBack = useCallback(() => {
    setView({ kind: "list" });
    setSearchErr(null);
  }, []);

  const openTx = useCallback(async (hash: string) => {
    setSearching(true);
    setSearchErr(null);
    try {
      const explorer = getExplorer();
      const tx = await explorer.getDecodedTransaction(hash);
      if (tx) {
        setView({ kind: "tx", tx });
      } else {
        setSearchErr("Transaction not found — it may have been rejected at submission (never mined).");
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
      const explorer = getExplorer();
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

  // Consume deep-link targets from parent (e.g. contract detail "open block/tx" links)
  useEffect(() => {
    if (initialBlockTarget != null) {
      openBlock(initialBlockTarget);
      onConsumeTarget?.();
    } else if (initialTxTarget != null) {
      openTx(initialTxTarget);
      onConsumeTarget?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialBlockTarget, initialTxTarget]);

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

  // Check if an address is a known contract escrow address
  const knownContractAddresses = new Set(contracts.map((c) => c.address.toLowerCase()));

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
          onSelectAddress={(addr) => setView({ kind: "account", address: addr })}
        />
      )}

      {view.kind === "tx" && (
        <TxDetail
          tx={view.tx}
          onClose={goBack}
          onSelectBlock={(n) => openBlock(n)}
          onSelectAddress={(addr) => setView({ kind: "account", address: addr })}
        />
      )}

      {view.kind === "account" && (
        <AccountView
          address={view.address}
          onClose={goBack}
          onSelectTx={openTx}
        />
      )}

      {/* Tab switcher: Blocks | Contracts */}
      <div className="card" style={{ padding: "0" }}>
        <div
          style={{
            display: "flex",
            borderBottom: "1px solid var(--line)",
          }}
        >
          {(["blocks", "contracts"] as ExplorerTab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                flex: 1,
                padding: "0.85rem 1rem",
                background: "transparent",
                border: "none",
                borderBottom: activeTab === tab ? "2px solid var(--accent)" : "2px solid transparent",
                color: activeTab === tab ? "var(--ink)" : "var(--muted)",
                fontWeight: activeTab === tab ? 600 : 400,
                fontSize: "0.85rem",
                cursor: "pointer",
                transition: "color .15s",
                fontFamily: "inherit",
                letterSpacing: "-.01em",
              }}
            >
              {tab === "blocks" ? "Blocks" : "Contracts"}
            </button>
          ))}
        </div>

        {/* Blocks tab */}
        {activeTab === "blocks" && (
          <div style={{ padding: "18px 22px" }}>
            <div className="card-header" style={{ marginBottom: "0.85rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                <h3 style={{ margin: 0 }}>Latest blocks</h3>
                <span className="tag green">live</span>
              </div>
              {/* Non-empty toggle */}
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  cursor: "pointer",
                  fontSize: "0.8rem",
                  color: "var(--muted)",
                  userSelect: "none",
                }}
              >
                <div
                  onClick={() => setNonEmptyOnly((v) => !v)}
                  style={{
                    width: "34px",
                    height: "18px",
                    borderRadius: "9px",
                    background: nonEmptyOnly ? "var(--accent)" : "var(--glass-2)",
                    border: `1px solid ${nonEmptyOnly ? "var(--accent)" : "var(--line-2)"}`,
                    position: "relative",
                    transition: "background .18s, border-color .18s",
                    flexShrink: 0,
                  }}
                >
                  <div
                    style={{
                      position: "absolute",
                      top: "2px",
                      left: nonEmptyOnly ? "17px" : "2px",
                      width: "12px",
                      height: "12px",
                      borderRadius: "50%",
                      background: nonEmptyOnly ? "#07080c" : "var(--muted)",
                      transition: "left .18s",
                    }}
                  />
                </div>
                <span>Non-empty only</span>
              </label>
            </div>

            {nonEmptyOnly && (
              <div
                className="muted small"
                style={{ marginBottom: "0.75rem", fontSize: "0.74rem", lineHeight: 1.5 }}
              >
                Showing blocks that contain at least one transaction. Toggle off to see all blocks
                including empty tick-blocks.
              </div>
            )}

            {blocksLoading && blocks.length === 0 ? (
              <p className="muted small">Loading blocks…</p>
            ) : blocks.length === 0 ? (
              <p className="muted small">
                {nonEmptyOnly
                  ? "No blocks with transactions found yet — the chain may only have empty tick-blocks so far."
                  : "No blocks yet — is the node running?"}
              </p>
            ) : (
              <div className="block-list">
                {blocks.map((b, i) => {
                  const num = parseInt(b.number, 16);
                  const txCount = b.txCount;
                  return (
                    <div
                      className="block-row"
                      key={b.hash || b.number}
                      style={{
                        cursor: "pointer",
                        transition: "background .12s",
                        borderRadius: "8px",
                        padding: ".6rem .5rem",
                        borderTop: i === 0 ? "none" : "1px solid var(--line)",
                      }}
                      onClick={() => openBlock(num)}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--glass-2)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <span className="block-num">#{num}</span>
                      <span className="block-hash">{shortHash(b.hash)}</span>
                      <span
                        className="muted small"
                        style={{
                          color: txCount > 0 ? "var(--accent)" : "var(--faint)",
                          fontWeight: txCount > 0 ? 600 : 400,
                        }}
                      >
                        {txCount} tx{txCount !== 1 ? "s" : ""}
                      </span>
                      <span className="block-ts">{fmtTs(b.timestamp)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Contracts tab */}
        {activeTab === "contracts" && (
          <div style={{ padding: "18px 22px" }}>
            <div className="card-header" style={{ marginBottom: "0.85rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                <h3 style={{ margin: 0 }}>Contract directory</h3>
                <span className="tag violet">on-chain</span>
              </div>
              <span className="muted small" style={{ fontSize: "0.72rem" }}>
                {contracts.length} contract{contracts.length !== 1 ? "s" : ""}
              </span>
            </div>

            {contractsLoading && contracts.length === 0 ? (
              <p className="muted small">Loading contracts…</p>
            ) : contracts.length === 0 ? (
              <p className="muted small">
                No contracts deployed yet. Deploy one in the Contracts tab.
              </p>
            ) : (
              <div>
                {contracts.map((c, i) => {
                  const escrowBig = (() => { try { return BigInt(c.escrow); } catch { return 0n; } })();
                  const statusCls = c.status === "Active" ? "pill active" : "pill stopped";
                  return (
                    <div
                      key={c.id}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "4rem 1fr auto",
                        gap: "0.75rem",
                        alignItems: "center",
                        padding: ".75rem .5rem",
                        borderTop: i === 0 ? "none" : "1px solid var(--line)",
                        cursor: "pointer",
                        transition: "background .12s",
                        borderRadius: "8px",
                      }}
                      onClick={() => setView({ kind: "account", address: c.address })}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--glass-2)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <div>
                        <span className="block-num">#{c.id}</span>
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div
                          style={{
                            fontSize: "0.8rem",
                            color: "var(--ink)",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            marginBottom: "0.2rem",
                          }}
                        >
                          {c.title || "(no title)"}
                        </div>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "0.5rem",
                            flexWrap: "wrap",
                          }}
                        >
                          <span
                            style={{
                              fontFamily: "var(--mono)",
                              fontSize: "0.7rem",
                              color: "var(--faint)",
                            }}
                          >
                            {short(c.address)}
                            <ContractBadge />
                          </span>
                          <span className={statusCls} style={{ fontSize: "0.58rem" }}>
                            {c.status}
                          </span>
                          <span className="muted small" style={{ fontSize: "0.7rem" }}>
                            {c.parties.length} {c.parties.length === 1 ? "party" : "parties"}
                          </span>
                          <span
                            style={{
                              fontSize: "0.7rem",
                              fontFamily: "var(--mono)",
                              color: escrowBig > 0n ? "var(--accent)" : "var(--faint)",
                            }}
                          >
                            {hexToUbi(c.escrow, 4)}
                          </span>
                        </div>
                      </div>
                      <div style={{ textAlign: "right" }}>
                        <div className="muted small" style={{ fontSize: "0.68rem" }}>
                          block #{c.deploy_block}
                        </div>
                        <div className="muted small" style={{ fontSize: "0.65rem" }}>
                          {fmtUnixTs(c.createdAt)}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <div
              className="muted small"
              style={{ marginTop: "0.85rem", fontSize: "0.72rem", lineHeight: 1.5 }}
            >
              Contract escrow addresses are marked with a{" "}
              <ContractBadge />{" "}
              badge throughout the explorer. Click any contract to view its account.
            </div>
          </div>
        )}
      </div>

      {/* Address-level contract badge legend */}
      {knownContractAddresses.size > 0 && view.kind === "account" && (
        <div
          className="card"
          style={{ padding: "0.65rem 1rem", fontSize: "0.75rem", color: "var(--muted)" }}
        >
          {knownContractAddresses.has(view.address.toLowerCase()) && (
            <span>
              This address is a contract escrow <ContractBadge />
            </span>
          )}
        </div>
      )}
    </div>
  );
}
