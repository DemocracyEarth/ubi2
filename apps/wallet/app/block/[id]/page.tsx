"use client";

/**
 * /block/[id] — standalone block detail page.
 *
 * [id] can be a decimal block number (e.g. /block/42), a hex number
 * (e.g. /block/0x2a), or "latest". Cross-links txs → /tx/<hash>
 * and miner address → /address/<addr>.
 */

import { use } from "react";
import { BlockPageContent } from "../../explorer-components";
import { ExplorerPageShell } from "../../explorer-page-shell";

export default function BlockPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const label = /^\d+$/.test(id) ? `Block #${id}` : `Block ${id}`;

  return (
    <ExplorerPageShell title={label} subtitle={id}>
      <BlockPageContent
        id={id}
        onSelectTx={(hash) => {
          window.location.href = `/tx/${hash}`;
        }}
        onSelectAddress={(addr) => {
          window.location.href = `/address/${addr}`;
        }}
      />
    </ExplorerPageShell>
  );
}
