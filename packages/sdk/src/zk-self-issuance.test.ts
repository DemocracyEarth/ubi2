import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, stringToBytes, toFunctionSelector } from "viem";
import {
  deserializeZkSelfIssuanceAuthorization,
  encodeZkSelfIssuance,
  recoverZkSelfIssuanceAuthority,
  serializeZkSelfIssuanceAuthorization,
  ZK_SELF_ISSUANCE_MAX_AUTHORIZATION_LIFETIME_SECONDS,
  zkSelfIssuanceAuthorizationDigest,
  zkSelfIssuanceDuplicateKey,
  zkSelfIssuanceTypedData,
  zkSelfVerifierConfigId,
  type ZkSelfIssuanceAuthorization,
} from "./zk-self-issuance";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";

const chainId = 84_532;
assert.equal(ZK_SELF_ISSUANCE_MAX_AUTHORIZATION_LIFETIME_SECONDS, 600n);
const bridge = "0x2222222222222222222222222222222222222222" as const;
const issuanceDomain =
  "0x3bf5571a5fb54037b033765a46a43d150ae8ffa32cb5c72c2ec11f6a572bd998" as const;
const selfConfigId = zkSelfVerifierConfigId({
  scope: "proofofhumanity",
  endpoint: "https://app.proofofhumanity.id/api/self-verify",
  environment: "production",
  attestationId: 1,
  verifierPackage: "@selfxyz/core@1.0.8",
});
assert.equal(
  selfConfigId,
  "0x5522de6e6aaacab517c9b1dfaeab9aff9522c6623725a0ca527de7104a15d0f0",
  "the exact Self verifier trust configuration has a stable id",
);

const duplicateKey = zkSelfIssuanceDuplicateKey({
  issuanceDomain,
  selfNullifier: 123_456_789n,
});
assert.equal(
  duplicateKey,
  "0x5d1fb2d82d6d6af36ef419697779e6ab2173106f9826e253aa1bf5de8758b862",
  "the raw Self nullifier is transformed into a registry-scoped opaque key",
);
assert.notEqual(duplicateKey, `0x${123_456_789n.toString(16).padStart(64, "0")}`);

const authorization: ZkSelfIssuanceAuthorization = {
  subject: "0x3333333333333333333333333333333333333333",
  duplicateKey,
  credentialCommitment: 987_654_321n,
  issuerKeyId: keccak256(stringToBytes("issuer-key:self:testnet:v1")),
  expectedStatusId: 1,
  expectedEpoch: 230,
  deadline: 1_788_480_600n,
  selfConfigId,
};
assert.equal(
  zkSelfIssuanceAuthorizationDigest({ chainId, bridge, authorization }),
  "0xfa9072a678ce9aef6ff55be35e6b93ce741a773cffb44d8d31950c67a17a983b",
  "the bridge EIP-712 authorization digest is pinned",
);

const authority = privateKeyToAccount(
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
const signature = await authority.signTypedData(
  zkSelfIssuanceTypedData({ chainId, bridge, authorization }),
);
assert.equal(
  await recoverZkSelfIssuanceAuthority({ chainId, bridge, authorization, signature }),
  authority.address,
);
assert.notEqual(
  await recoverZkSelfIssuanceAuthority({ chainId: 1, bridge, authorization, signature }),
  authority.address,
  "a signature cannot cross chains",
);
assert.notEqual(
  await recoverZkSelfIssuanceAuthority({
    chainId,
    bridge: "0x4444444444444444444444444444444444444444",
    authorization,
    signature,
  }),
  authority.address,
  "a signature cannot cross bridge deployments",
);

const serialized = serializeZkSelfIssuanceAuthorization(authorization);
assert.equal(serialized.credentialCommitment, "987654321");
assert.equal(serialized.deadline, "1788480600");
assert.deepEqual(deserializeZkSelfIssuanceAuthorization(serialized), authorization);
assert.equal(
  encodeZkSelfIssuance({ authorization: serialized, signature }).slice(0, 10),
  toFunctionSelector(
    "issue((address,bytes32,uint256,bytes32,uint32,uint32,uint64,bytes32),bytes)",
  ),
  "the SDK emits calldata for the exact bridge tuple layout",
);

assert.throws(
  () => zkSelfIssuanceDuplicateKey({ issuanceDomain, selfNullifier: 0n }),
  /Self nullifier/u,
);
assert.throws(
  () => zkSelfIssuanceDuplicateKey({ issuanceDomain, selfNullifier: BN254_SCALAR_FIELD }),
  /Self nullifier/u,
);
assert.throws(
  () =>
    zkSelfVerifierConfigId({
      scope: "proofofhumanity",
      endpoint: " https://app.proofofhumanity.id/api/self-verify",
      environment: "production",
      attestationId: 1,
      verifierPackage: "@selfxyz/core@1.0.8",
    }),
  /Self endpoint/u,
);
assert.throws(
  () =>
    serializeZkSelfIssuanceAuthorization({
      ...authorization,
      credentialCommitment: BN254_SCALAR_FIELD,
    }),
  /credential commitment/u,
);
