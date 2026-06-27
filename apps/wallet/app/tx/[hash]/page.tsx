"use client";

/**
 * /tx/[hash] — standalone transaction detail page.
 *
 * MetaMask appends /tx/<hash> to the blockExplorerUrls when showing
 * "View on explorer". This page fetches and renders the decoded transaction.
 *
 * Not-found state: a hash that the node never indexed shows a clear explanation
 * (rejected at submission, never mined) instead of a bare 404.
 */

import { use } from "react";
import { TxPageContent } from "../../explorer-components";
import { ExplorerPageShell } from "../../explorer-page-shell";

export default function TxPage({
  params,
}: {
  params: Promise<{ hash: string }>;
}) {
  const { hash } = use(params);

  return (
    <ExplorerPageShell title="Transaction" subtitle={hash}>
      <TxPageContent
        hash={hash}
        onSelectBlock={(n) => {
          window.location.href = `/block/${n}`;
        }}
        onSelectAddress={(addr) => {
          window.location.href = `/address/${addr}`;
        }}
      />
    </ExplorerPageShell>
  );
}
