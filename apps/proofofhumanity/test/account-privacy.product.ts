import assert from "node:assert/strict";
import { getAddress, type Address } from "viem";
import {
  ACCOUNT_PRIVACY_REASON_LABELS,
  accountPrivacyFindingReasons,
  resolveWalletAccountChange,
  sameWalletAccount,
  scanAccountPrivacy,
  type AccountPrivacyChain,
  type AccountPrivacySignals,
} from "../app/lib/account-privacy";

const account = getAddress("0x1111111111111111111111111111111111111111");
const otherAccount = getAddress("0x2222222222222222222222222222222222222222");
const chains = [
  { chainId: 1, name: "Clear Chain" },
  { chainId: 2, name: "Activity Chain" },
  { chainId: 3, name: "Unavailable Chain" },
] satisfies AccountPrivacyChain[];
const clearSignals: AccountPrivacySignals = {
  transactionCount: 0,
  nativeBalance: 0n,
  bytecode: "0x",
  pohBalance: 0n,
};

async function main(): Promise<void> {
  assert.deepEqual(accountPrivacyFindingReasons(clearSignals), []);
  assert.deepEqual(
    accountPrivacyFindingReasons({
      transactionCount: 2,
      nativeBalance: 1n,
      bytecode: "0x6000",
      pohBalance: 1n,
    }),
    ["existing-poh-credential", "sent-transactions", "native-balance", "contract-code"],
  );
  assert.throws(
    () => accountPrivacyFindingReasons({ ...clearSignals, transactionCount: -1 }),
    /non-negative safe integer/u,
  );

  const assessment = await scanAccountPrivacy({
    account,
    chains,
    probe: async (chain, probedAccount) => {
      assert.equal(probedAccount, account);
      if (chain.chainId === 3) throw new Error("https://secret-rpc.example/project-key");
      return chain.chainId === 2
        ? { ...clearSignals, transactionCount: 1, nativeBalance: 5n }
        : clearSignals;
    },
  });
  assert.equal(assessment.status, "activity-detected");
  assert.equal(assessment.checkedChains, 2);
  assert.deepEqual(assessment.unavailableChains, ["Unavailable Chain"]);
  assert.deepEqual(assessment.findings, [
    {
      chainId: 2,
      chainName: "Activity Chain",
      reasons: ["sent-transactions", "native-balance"],
    },
  ]);
  assert.equal(JSON.stringify(assessment).includes("secret-rpc"), false);
  assert.equal(assessment.provesFreshness, false);

  const incomplete = await scanAccountPrivacy({
    account,
    chains: chains.slice(0, 2),
    probe: async (chain) => {
      if (chain.chainId === 2) throw new Error("offline");
      return clearSignals;
    },
  });
  assert.equal(incomplete.status, "incomplete");
  assert.deepEqual(incomplete.findings, []);

  const clear = await scanAccountPrivacy({
    account,
    chains: chains.slice(0, 2),
    probe: async () => clearSignals,
  });
  assert.equal(clear.status, "no-obvious-activity");
  assert.equal(clear.checkedChains, 2);

  const noConfiguredChains = await scanAccountPrivacy({
    account,
    chains: [],
    probe: async () => clearSignals,
  });
  assert.equal(noConfiguredChains.status, "incomplete");
  assert.equal(noConfiguredChains.checkedChains, 0);

  assert.deepEqual(resolveWalletAccountChange(null, [account]), {
    account,
    invalidatesSession: false,
  });
  assert.deepEqual(resolveWalletAccountChange(account.toLowerCase() as Address, [account]), {
    account,
    invalidatesSession: false,
  });
  assert.deepEqual(resolveWalletAccountChange(account, [otherAccount]), {
    account: otherAccount,
    invalidatesSession: true,
  });
  assert.deepEqual(resolveWalletAccountChange(account, []), {
    account: null,
    invalidatesSession: true,
  });
  assert.deepEqual(resolveWalletAccountChange(account, ["not-an-address"]), {
    account: null,
    invalidatesSession: true,
  });
  assert.equal(sameWalletAccount(account, account.toLowerCase()), true);
  assert.equal(sameWalletAccount(account, otherAccount), false);
  assert.equal(sameWalletAccount(account, null), false);
  assert.equal(ACCOUNT_PRIVACY_REASON_LABELS["native-balance"].includes("funding"), true);

  const probedAccounts: Address[] = [];
  await scanAccountPrivacy({
    account,
    chains: [{ chainId: 10, name: "One" }],
    probe: async (_chain, probedAccount) => {
      probedAccounts.push(probedAccount);
      return clearSignals;
    },
  });
  assert.deepEqual(probedAccounts, [account]);
  await assert.rejects(
    scanAccountPrivacy({
      account,
      chains: [
        { chainId: 10, name: "One" },
        { chainId: 10, name: "Duplicate" },
      ],
      probe: async () => clearSignals,
    }),
    /chain ids must be unique/u,
  );

  console.log("account privacy: acknowledgment support + warning-only scan + wallet-change semantics PASS");
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
