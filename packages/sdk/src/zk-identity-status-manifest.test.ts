import assert from "node:assert/strict";
import { keccak256, stringToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  assertDynamicStatusManifestCurrent,
  createDynamicStatusManifest,
  dynamicStatusManifestDigest,
  dynamicStatusManifestTypedData,
  parseDynamicStatusManifest,
  recoverDynamicStatusManifestSigner,
  serializeDynamicStatusManifest,
  verifyDynamicStatusManifestSignature,
} from "./zk-identity-status-manifest";

const publisher = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8411ddca14bb03ea63",
);
const otherPublisher = privateKeyToAccount(
  "0x8b3a350cf5c34c9194ca3a545d4f80aa3102b4c3b8d1b5e1d4f6f7c8d9e0a123",
);
const input = {
  chainId: 84_532,
  registry: "0x1111111111111111111111111111111111111111" as const,
  policy: {
    kind: "dynamic-status" as const,
    status: "sanctions-clear" as const,
    providerId: "self:ofac",
    listVersion: "2026-08-12",
    statusRoot: keccak256(stringToBytes("demo status root")),
    maximumAgeSeconds: 86_400,
  },
  publishedAt: 1_786_492_800,
};

const manifest = createDynamicStatusManifest(input);
assert.equal(manifest.policyHash, "0x554b29b8540ffafa1fa4bc6e54847f887d03b4b9b29449ba2418cbc7f9fa3381");
assert.equal(manifest.expiresAt, 1_786_579_200);
assert.deepEqual(parseDynamicStatusManifest(JSON.parse(serializeDynamicStatusManifest(manifest))), manifest);
assert.equal(
  dynamicStatusManifestDigest(manifest),
  "0x1edd5076cd5e71cb68f74e27366a6a056138da96e1bffd8db4f33e057a917f5b",
  "manifest digest is pinned across publisher tooling",
);

const signature = await publisher.signTypedData(dynamicStatusManifestTypedData(manifest));
assert.equal(await recoverDynamicStatusManifestSigner(manifest, signature), publisher.address);
assert.equal(await verifyDynamicStatusManifestSignature(manifest, signature, publisher.address), true);
assert.equal(await verifyDynamicStatusManifestSignature(manifest, signature, otherPublisher.address), false);
assert.equal(await verifyDynamicStatusManifestSignature(manifest, "0x12", publisher.address), false);

const otherChain = createDynamicStatusManifest({ ...input, chainId: 1 });
const otherRegistry = createDynamicStatusManifest({
  ...input,
  registry: "0x2222222222222222222222222222222222222222",
});
assert.notEqual(dynamicStatusManifestDigest(otherChain), dynamicStatusManifestDigest(manifest));
assert.notEqual(dynamicStatusManifestDigest(otherRegistry), dynamicStatusManifestDigest(manifest));
assert.equal(await verifyDynamicStatusManifestSignature(otherChain, signature, publisher.address), false);
assert.equal(await verifyDynamicStatusManifestSignature(otherRegistry, signature, publisher.address), false);

assert.deepEqual(assertDynamicStatusManifestCurrent(manifest, manifest.publishedAt), manifest);
assert.deepEqual(assertDynamicStatusManifestCurrent(manifest, manifest.expiresAt), manifest);
assert.throws(() => assertDynamicStatusManifestCurrent(manifest, manifest.publishedAt - 1), /future/u);
assert.throws(() => assertDynamicStatusManifestCurrent(manifest, manifest.expiresAt + 1), /stale/u);

assert.throws(
  () => parseDynamicStatusManifest({ ...manifest, providerId: "other:provider" }),
  /does not match canonical metadata/u,
);
assert.throws(
  () => parseDynamicStatusManifest({ ...manifest, expiresAt: manifest.expiresAt + 1 }),
  /expiry/u,
);
assert.throws(
  () => parseDynamicStatusManifest({ ...manifest, injected: true }),
  /missing or unknown fields/u,
);
assert.throws(
  () =>
    createDynamicStatusManifest({
      ...input,
      policy: { ...input.policy, statusRoot: `0x${"00".repeat(32)}` },
    }),
  /status root must not be zero/u,
);

console.log("zk dynamic-status manifest: canonical EIP-712 auth + freshness PASS");
