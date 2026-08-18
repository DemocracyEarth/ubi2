import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { keccak256, stringToHex } from "viem";
import { ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256 } from "./zk-holder-profile-prover-worker";

const repository = fileURLToPath(new URL("../../..", import.meta.url));

async function fixture(name: string): Promise<Record<string, unknown>> {
  return JSON.parse(
    await readFile(`${repository}/fixtures/v2-production-crypto/${name}`, "utf8"),
  ) as Record<string, unknown>;
}

const [parameters, vector, signals, circuits, browserArtifacts, browserWasm, frozenInterface] = await Promise.all([
  fixture("parameters-v1.json"),
  fixture("reference-vector-v1.json"),
  fixture("public-signals-v1.json"),
  fixture("circuit-set-v1.json"),
  fixture("holder-profile-browser-artifacts-v1.json"),
  readFile(`${repository}/fixtures/v2-production-crypto/holder-profile-synthetic-v1.wasm`),
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
assert.equal(browserArtifacts.profileId, profileId);
assert.equal(browserArtifacts.mode, "synthetic");
assert.equal(browserArtifacts.presentationReady, false);
const browserArtifact = (browserArtifacts.artifacts as Array<{ sha256: string; bytes: number }>)[0]!;
assert.equal(browserArtifact.sha256, ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256.slice(2));
assert.equal(browserArtifact.bytes, browserWasm.byteLength);
assert.equal(createHash("sha256").update(browserWasm).digest("hex"), browserArtifact.sha256);

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
