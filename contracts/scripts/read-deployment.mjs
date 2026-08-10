#!/usr/bin/env node

import { readFileSync } from "node:fs";

const [manifestPath, field = "summary"] = process.argv.slice(2);
if (!manifestPath) {
  console.error("usage: read-deployment.mjs <run-latest.json> [renderer|poh|predicate|summary]");
  process.exit(2);
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
if (!Array.isArray(manifest.transactions)) {
  throw new Error(`${manifestPath} does not contain a Foundry transactions array`);
}

function deployment(contractName) {
  const matches = manifest.transactions.filter(
    (transaction) =>
      transaction.contractName === contractName &&
      transaction.contractAddress &&
      String(transaction.transactionType).startsWith("CREATE"),
  );
  if (matches.length !== 1) {
    throw new Error(`expected exactly one ${contractName} deployment; found ${matches.length}`);
  }

  const transaction = matches[0];
  return {
    address: transaction.contractAddress,
    txHash: transaction.hash ?? transaction.transactionHash ?? null,
  };
}

if (manifest.transactions.some((transaction) => transaction.contractName === "SybilResistantVote")) {
  throw new Error("broadcast manifest contains forbidden production deployment SybilResistantVote");
}

const deployments = {
  renderer: deployment("PoHCardRenderer"),
  poh: deployment("ProofOfHumanity"),
  predicate: deployment("PredicateVerifier"),
};

if (field === "summary") {
  console.log(JSON.stringify(deployments, null, 2));
} else if (field in deployments) {
  console.log(deployments[field].address);
} else {
  console.error(`unknown field: ${field}`);
  process.exit(2);
}
