#!/usr/bin/env node

import { readFileSync } from "node:fs";

const [reportPath = "lcov.info", thresholdArg = "95"] = process.argv.slice(2);
const threshold = Number(thresholdArg);

if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
  throw new Error(`coverage threshold must be between 0 and 100; received ${thresholdArg}`);
}

const targets = new Map([
  ["src/ProofOfHumanity.sol", { linesFound: 0, linesHit: 0, branchesFound: 0, branchesHit: 0 }],
  ["src/PredicateVerifier.sol", { linesFound: 0, linesHit: 0, branchesFound: 0, branchesHit: 0 }],
]);

const records = readFileSync(reportPath, "utf8").split("end_of_record");
for (const record of records) {
  const source = record.match(/^SF:(.+)$/m)?.[1]?.replaceAll("\\", "/");
  if (!source) continue;

  const target = [...targets.keys()].find((candidate) => source.endsWith(candidate));
  if (!target) continue;

  const totals = targets.get(target);
  totals.linesFound += Number(record.match(/^LF:(\d+)$/m)?.[1] ?? 0);
  totals.linesHit += Number(record.match(/^LH:(\d+)$/m)?.[1] ?? 0);
  totals.branchesFound += Number(record.match(/^BRF:(\d+)$/m)?.[1] ?? 0);
  totals.branchesHit += Number(record.match(/^BRH:(\d+)$/m)?.[1] ?? 0);
}

function percentage(hit, found) {
  return found === 0 ? 0 : (hit * 100) / found;
}

let failed = false;
console.log(`Target contract coverage (minimum ${threshold.toFixed(2)}%)`);
console.log("contract                     lines             branches");

for (const [target, totals] of targets) {
  if (totals.linesFound === 0 || totals.branchesFound === 0) {
    console.error(`ERROR: ${target} is missing line or branch data in ${reportPath}`);
    failed = true;
    continue;
  }

  const lineCoverage = percentage(totals.linesHit, totals.linesFound);
  const branchCoverage = percentage(totals.branchesHit, totals.branchesFound);
  console.log(
    `${target.padEnd(28)} ${lineCoverage.toFixed(2).padStart(6)}% (${totals.linesHit}/${totals.linesFound})   ` +
      `${branchCoverage.toFixed(2).padStart(6)}% (${totals.branchesHit}/${totals.branchesFound})`,
  );

  if (lineCoverage < threshold || branchCoverage < threshold) failed = true;
}

if (failed) {
  console.error("ERROR: target-contract line/branch coverage gate failed");
  process.exit(1);
}
