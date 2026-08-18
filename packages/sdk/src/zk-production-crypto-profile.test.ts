import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { keccak256, stringToHex } from "viem";

const repository = fileURLToPath(new URL("../../..", import.meta.url));

async function fixture(name: string): Promise<Record<string, unknown>> {
  return JSON.parse(
    await readFile(`${repository}/fixtures/v2-production-crypto/${name}`, "utf8"),
  ) as Record<string, unknown>;
}

const [parameters, vector, signals, circuits, frozenInterface] = await Promise.all([
  fixture("parameters-v1.json"),
  fixture("reference-vector-v1.json"),
  fixture("public-signals-v1.json"),
  fixture("circuit-set-v1.json"),
  JSON.parse(
    await readFile(`${repository}/fixtures/v2-identity/interface-v1.json`, "utf8"),
  ) as {
    publicSignals: { names: string[] };
  },
]);

const profileId = "org.proofofhumanity.v2-crypto.groth16-bn254-poseidon/1";
assert.equal(parameters.profileId, profileId);
assert.equal(vector.profileId, profileId);
assert.equal(signals.profileId, profileId);
assert.equal(circuits.profileId, profileId);

const signalRows = signals.signals as Array<{ index: number; name: string }>;
assert.equal(signalRows.length, 18);
assert.deepEqual(
  signalRows.map(({ index }) => index),
  Array.from({ length: 18 }, (_, index) => index),
);
assert.deepEqual(
  signalRows.map(({ name }) => name),
  frozenInterface.publicSignals.names,
  "profile ratification must preserve the frozen 18-signal ABI",
);
assert.deepEqual(vector.publicSignalNames, frozenInterface.publicSignals.names);
assert.equal((vector.publicSignals as string[]).length, 18);

for (const circuit of circuits.circuits as Array<{
  circuitId: `0x${string}`;
  idPreimage: string;
}>) {
  assert.equal(
    circuit.circuitId,
    keccak256(stringToHex(circuit.idPreimage)),
    `${circuit.idPreimage} circuit id must be content-derived`,
  );
}

const privateSyntheticCredential = vector.privateSyntheticCredential as {
  nationality: string;
  issuingState: string;
};
assert.equal(privateSyntheticCredential.nationality, "XAA");
assert.equal(privateSyntheticCredential.issuingState, "XAB");
assert.match(String(vector.warning), /synthetic/u);

console.log("v2 production cryptographic profile vectors: ok");
