import { getAddress, isAddress, type Address, type Hex } from "viem";

export type AccountPrivacyFindingReason =
  | "existing-poh-credential"
  | "sent-transactions"
  | "native-balance"
  | "contract-code";

export const ACCOUNT_PRIVACY_REASON_LABELS: Record<AccountPrivacyFindingReason, string> = {
  "existing-poh-credential": "existing Proof of Humanity credential",
  "sent-transactions": "sent transaction history",
  "native-balance": "native-token balance or prior funding",
  "contract-code": "contract or delegated-account code",
};

export interface AccountPrivacyChain {
  chainId: number;
  name: string;
}

export interface AccountPrivacySignals {
  transactionCount: number;
  nativeBalance: bigint;
  bytecode: Hex | undefined;
  pohBalance: bigint;
}

export interface AccountPrivacyFinding {
  chainId: number;
  chainName: string;
  reasons: AccountPrivacyFindingReason[];
}

export interface AccountPrivacyAssessment {
  status: "no-obvious-activity" | "activity-detected" | "incomplete";
  checkedChains: number;
  unavailableChains: string[];
  findings: AccountPrivacyFinding[];
  /** This heuristic can never prove that an address is fresh or unlinkable. */
  provesFreshness: false;
}

export interface WalletAccountChange {
  account: Address | null;
  invalidatesSession: boolean;
}

function canonicalAccount(value: unknown): Address | null {
  return typeof value === "string" && isAddress(value) ? getAddress(value) : null;
}

export function sameWalletAccount(left: unknown, right: unknown): boolean {
  const normalizedLeft = canonicalAccount(left);
  const normalizedRight = canonicalAccount(right);
  return normalizedLeft !== null && normalizedLeft === normalizedRight;
}

/** Resolve an EIP-1193 accountsChanged payload without trusting malformed provider data. */
export function resolveWalletAccountChange(
  previous: Address | null,
  accounts: readonly unknown[],
): WalletAccountChange {
  const account = canonicalAccount(accounts[0]);
  return {
    account,
    invalidatesSession: previous !== null && !sameWalletAccount(account, previous),
  };
}

export function accountPrivacyFindingReasons(
  signals: AccountPrivacySignals,
): AccountPrivacyFindingReason[] {
  if (!Number.isSafeInteger(signals.transactionCount) || signals.transactionCount < 0) {
    throw new Error("account activity transaction count must be a non-negative safe integer");
  }
  if (signals.nativeBalance < 0n || signals.pohBalance < 0n) {
    throw new Error("account activity balances must not be negative");
  }
  const reasons: AccountPrivacyFindingReason[] = [];
  if (signals.pohBalance > 0n) reasons.push("existing-poh-credential");
  if (signals.transactionCount > 0) reasons.push("sent-transactions");
  if (signals.nativeBalance > 0n) reasons.push("native-balance");
  if (signals.bytecode !== undefined && signals.bytecode !== "0x") reasons.push("contract-code");
  return reasons;
}

/**
 * Run a warning-only activity heuristic. Probe failures are reduced to chain
 * names so RPC URLs and provider diagnostics never enter UI state.
 */
export async function scanAccountPrivacy<TChain extends AccountPrivacyChain>(input: {
  account: Address;
  chains: readonly TChain[];
  probe: (chain: TChain, account: Address) => Promise<AccountPrivacySignals>;
}): Promise<AccountPrivacyAssessment> {
  const account = canonicalAccount(input.account);
  if (account === null) throw new Error("account activity scan requires a valid address");
  if (new Set(input.chains.map(({ chainId }) => chainId)).size !== input.chains.length) {
    throw new Error("account activity scan chain ids must be unique");
  }

  const observations = await Promise.all(
    input.chains.map(async (chain) => {
      try {
        const reasons = accountPrivacyFindingReasons(await input.probe(chain, account));
        return { chain, reasons, available: true as const };
      } catch {
        return { chain, available: false as const };
      }
    }),
  );
  const available = observations.filter(
    (observation): observation is Extract<(typeof observations)[number], { available: true }> =>
      observation.available,
  );
  const unavailableChains = observations
    .filter(({ available }) => !available)
    .map(({ chain }) => chain.name)
    .sort();
  const findings = available
    .filter(({ reasons }) => reasons.length > 0)
    .map(({ chain, reasons }) => ({
      chainId: chain.chainId,
      chainName: chain.name,
      reasons,
    }))
    .sort((left, right) => left.chainId - right.chainId);

  return {
    status:
      findings.length > 0
        ? "activity-detected"
        : unavailableChains.length > 0 || available.length === 0
          ? "incomplete"
          : "no-obvious-activity",
    checkedChains: available.length,
    unavailableChains,
    findings,
    provesFreshness: false,
  };
}
