"use client";

/**
 * /address/[addr] — standalone account detail page.
 *
 * MetaMask appends /address/<addr> when "View on explorer" is triggered
 * for an account. Shows account summary + activity via ubi_getAccount
 * and ubi_getAddressActivity. Activity rows link to /tx/<hash>.
 */

import { use } from "react";
import { AddressPageContent } from "../../explorer-components";
import { ExplorerPageShell } from "../../explorer-page-shell";

export default function AddressPage({
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
