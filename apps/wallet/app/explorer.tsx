"use client";

/**
 * Deep block explorer — obsidian-glass, cycle-5.
 * Search by address / tx hash / block number.
 * Block page: full header fields + decoded tx list (ubi_getBlock).
 * Tx page: from/to/fee, decoded hub call, decoded logs, result (ubi_getTransaction).
 * Account page: ubi_getAccount + ubi_getAddressActivity.
 * Latest blocks list polling every 4 s.
 *
 * Detail views are also available as URL-addressable routes:
 *   /tx/[hash], /block/[id], /address/[addr], /account/[addr]
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Ubi2Client,
  type Block,
  type DecodedTransaction,
  type DecodedBlock,
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

const MAX_BLOCKS = 10;
const POLL_MS = 4000;

// ---- Main Explorer Component ----------------------------------------------------------

type View =
  | { kind: "list" }
  | { kind: "block"; block: DecodedBlock }
  | { kind: "tx"; tx: DecodedTransaction }
  | { kind: "account"; address: string };

interface ExplorerProps {
  /** Deep-link: open this block number on mount (consumed once). */
  initialBlockTarget?: number | null;
  /** Deep-link: open this tx hash on mount (consumed once). */
  initialTxTarget?: string | null;
  /** Called after the initial target has been consumed so the parent can clear it. */
  onConsumeTarget?: () => void;
}

export function Explorer({ initialBlockTarget, initialTxTarget, onConsumeTarget }: ExplorerProps = {}) {
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
