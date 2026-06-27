"use client";

/**
 * /account/[addr] — alias for /address/[addr].
 *
 * Some MetaMask versions or third-party tools use /account/<addr>
 * rather than /address/<addr>. This route is identical in behavior.
 */

import { use } from "react";
import { AddressPageContent } from "../../explorer-components";
import { ExplorerPageShell } from "../../explorer-page-shell";

export default function AccountPage({
  params,
}: {
  params: Promise<{ addr: string }>;
}) {
  const { addr } = use(params);

  return (
    <ExplorerPageShell title="Account" subtitle={addr}>
      <AddressPageContent
        address={addr}
        onSelectTx={(hash) => {
          window.location.href = `/tx/${hash}`;
        }}
      />
    </ExplorerPageShell>
  );
}
