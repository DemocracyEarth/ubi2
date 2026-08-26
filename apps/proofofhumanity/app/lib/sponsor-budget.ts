export type SponsorBudgetAlert = "balance-above-cap" | "daily-spend-high" | "reserve-low";

export interface SponsorBudgetSnapshot {
  balanceWei: bigint;
  dailySpendWei: bigint;
}

export interface SponsorBudgetPolicy {
  minimumReserveWei: bigint;
  maximumBalanceWei: bigint;
  dailySpendLimitWei: bigint;
}

/** Include an OP Stack receipt's optional L1 data fee in native-token spend. */
export function sponsorTransactionSpendWei(input: {
  gasUsed: bigint;
  effectiveGasPrice: bigint;
  l1FeeWei?: bigint;
  successfulValueWei?: bigint;
}): bigint {
  return (
    input.gasUsed * input.effectiveGasPrice +
    (input.l1FeeWei ?? 0n) +
    (input.successfulValueWei ?? 0n)
  );
}

/** Evaluate the public native-token telemetry used by the staging sponsor alarm. */
export function evaluateSponsorBudget(
  snapshot: SponsorBudgetSnapshot,
  policy: SponsorBudgetPolicy,
): SponsorBudgetAlert[] {
  const alerts: SponsorBudgetAlert[] = [];
  if (snapshot.balanceWei < policy.minimumReserveWei) alerts.push("reserve-low");
  if (snapshot.balanceWei > policy.maximumBalanceWei) alerts.push("balance-above-cap");
  if (snapshot.dailySpendWei > policy.dailySpendLimitWei) alerts.push("daily-spend-high");
  return alerts;
}
