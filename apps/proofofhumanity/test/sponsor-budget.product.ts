import assert from "node:assert/strict";
import { evaluateSponsorBudget, sponsorTransactionSpendWei } from "../app/lib/sponsor-budget";

const policy = {
  minimumReserveWei: 1_000n,
  maximumBalanceWei: 10_000n,
  dailySpendLimitWei: 2_000n,
};

assert.deepEqual(evaluateSponsorBudget({ balanceWei: 5_000n, dailySpendWei: 500n }, policy), []);
assert.deepEqual(evaluateSponsorBudget({ balanceWei: 999n, dailySpendWei: 500n }, policy), ["reserve-low"]);
assert.deepEqual(evaluateSponsorBudget({ balanceWei: 10_001n, dailySpendWei: 2_001n }, policy), [
  "balance-above-cap",
  "daily-spend-high",
]);
assert.deepEqual(evaluateSponsorBudget({ balanceWei: 0n, dailySpendWei: 3_000n }, policy), [
  "reserve-low",
  "daily-spend-high",
]);
assert.equal(
  sponsorTransactionSpendWei({
    gasUsed: 100n,
    effectiveGasPrice: 2n,
    l1FeeWei: 30n,
    successfulValueWei: 40n,
  }),
  270n,
);

console.log("sponsor budget policy: reserve, balance cap, and daily spend alerts passed");
