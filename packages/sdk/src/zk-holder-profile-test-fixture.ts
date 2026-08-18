import { toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createPasskeyProtectedCredentialVault,
  generatePasskeyPrfSalt,
} from "./credential-vault";
import {
  buildZkHolderIssuanceTranscript,
  ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA,
  ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME,
  ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA,
  ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA,
  type ZkHolderCredentialCommitment,
} from "./zk-holder-credential";
import {
  parseZkHolderReferenceVaultPayload,
  ZK_HOLDER_REFERENCE_PROFILE_STATUS,
  ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA,
  ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_VERSION,
  ZK_HOLDER_REFERENCE_WARNING,
} from "./zk-holder-reference-handoff";
import {
  serializeZkSelfIssuanceAuthorization,
  zkSelfIssuanceTypedData,
  type ZkSelfIssuanceArtifact,
  type ZkSelfIssuanceAuthorization,
} from "./zk-self-issuance";

export async function syntheticProfileVaultFixture() {
  const authority = privateKeyToAccount(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  );
  const chainId = 84_532;
  const bridge = "0x1111111111111111111111111111111111111111" as const;
  const registry = "0x2222222222222222222222222222222222222222" as const;
  const issuerKeyId =
    "0x0446b5caa8a2f7a9ed023dc9d2bc9f3a32a1515fce6450231ffd870b4d3fb412" as const;
  const commitment: ZkHolderCredentialCommitment = {
    schema: ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA,
    credentialSchema: ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA,
    commitmentScheme: ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME,
    issuerKeyId,
    statusId: 7,
    issuedAtEpoch: 230,
    commitment: toHex(
      5_836_928_380_906_255_446_748_790_206_300_639_901_721_220_972_022_839_770_207_472_017_463_583_976_253n,
      { size: 32 },
    ),
  };
  const authorization: ZkSelfIssuanceAuthorization = {
    subject: "0x3333333333333333333333333333333333333333",
    duplicateKey: `0x${"44".repeat(32)}`,
    credentialCommitment: BigInt(commitment.commitment),
    issuerKeyId,
    expectedStatusId: 7,
    expectedEpoch: 230,
    deadline: 1_900_000_000n,
    selfConfigId: `0x${"55".repeat(32)}`,
  };
  const artifact: ZkSelfIssuanceArtifact = {
    chainId,
    bridge,
    registry,
    authorization: serializeZkSelfIssuanceAuthorization(authorization),
    signature: await authority.signTypedData(zkSelfIssuanceTypedData({ chainId, bridge, authorization })),
  };
  const transcript = await buildZkHolderIssuanceTranscript({
    commitment,
    artifact,
    verificationAuthority: authority.address,
    allocation: {
      transactionHash: `0x${"66".repeat(32)}`,
      blockNumber: 20_001n,
      blockHash: `0x${"77".repeat(32)}`,
      logIndex: 2,
      issuerKeyId,
      statusId: 7,
      credentialCommitment: BigInt(commitment.commitment),
      issuedAtEpoch: 230,
    },
    statusSnapshot: {
      transactionHash: `0x${"88".repeat(32)}`,
      blockNumber: 20_009n,
      blockHash: `0x${"99".repeat(32)}`,
      logIndex: 1,
      snapshotId: 4,
      root: toHex(
        18_739_086_243_489_619_698_141_953_106_913_031_956_354_235_528_640_098_812_208_482_942_904_596_495_546n,
        { size: 32 },
      ),
      activatedThroughStatusId: 7,
      publishedAt: 1_788_480_000n,
    },
  });
  const payload = parseZkHolderReferenceVaultPayload({
    schema: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA,
    version: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_VERSION,
    profileStatus: ZK_HOLDER_REFERENCE_PROFILE_STATUS,
    warning: ZK_HOLDER_REFERENCE_WARNING,
    presentationReady: false,
    credential: {
      schema: ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA,
      issuerKeyId,
      statusId: 7,
      holderSecret: "123456789",
      credentialBlinding: "987654321",
      dateOfBirth: "2000-01-01",
      nationality: "XAA",
      issuingState: "XAB",
      expiryDate: "2030-01-01",
      documentClass: "epassport",
      assurance: "chip-auth",
      issuedAtEpoch: 230,
    },
    commitment,
    issuanceTranscript: transcript,
  });
  const credentialId = "c3ludGhldGljLXByb2ZpbGUtcGFzc2tleQ";
  const prfOutput = new Uint8Array(32).fill(0x42);
  const vault = await createPasskeyProtectedCredentialVault(
    payload,
    { schema: ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA, rpId: "proofofhumanity.org" },
    { credentialId, prfSalt: generatePasskeyPrfSalt(), prfOutput },
  );
  return { vault, credentialId, prfOutput, payload };
}
