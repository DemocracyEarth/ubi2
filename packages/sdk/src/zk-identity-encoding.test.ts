import assert from "node:assert/strict";
import { keccak256, stringToBytes, type Hex } from "viem";
import {
  BN254_SCALAR_FIELD,
  decodeZkIdentityPublicSignals,
  encodeZkPredicateProofContext,
  encodeZkIdentityPublicSignals,
  joinBytes32,
  serializeZkIdentityPublicSignals,
  splitBytes32,
  zkNullifierScopeHash,
  zkIssuanceDomainHash,
  zkPrivateCredentialFingerprint,
  zkScopedNullifierPreimage,
  ZK_PUBLIC_SIGNAL_COUNT,
  type ZkIdentityPublicSignalValues,
} from "./zk-identity-encoding";
import {
  dynamicStatusPolicyRegistration,
  zkPresentationBindingHash,
} from "./zk-identity-policy";

assert.equal(
  zkIssuanceDomainHash({
    chainId: 84_532,
    registry: "0x1111111111111111111111111111111111111111",
  }),
  "0x3bf5571a5fb54037b033765a46a43d150ae8ffa32cb5c72c2ec11f6a572bd998",
  "issuance domain is pinned across TypeScript and Solidity",
);
assert.throws(
  () =>
    zkIssuanceDomainHash({
      chainId: 0,
      registry: "0x1111111111111111111111111111111111111111",
    }),
  /issuance chain id/u,
);
assert.throws(
  () =>
    zkIssuanceDomainHash({
      chainId: 84_532,
      registry: "0x0000000000000000000000000000000000000000",
    }),
  /issuance registry must not be the zero address/u,
);

const issuerKeyId = keccak256(stringToBytes("issuer-key:testnet:v1"));
const statusId = keccak256(stringToBytes("status:fixture:1"));
const policyHash = "0x3f71ddd64fc1edef180756674529dd32b2c90f7288d2f0ced062e781a0cda3a2" as const;
const presentationBindingHash =
  "0xfcbaa318d3aba026a8827d332ec45ae24e9dbdd9ca6029b6fd3741b4e670e7a0" as const;

const credential = {
  issuerKeyId,
  statusId,
  holderSecret: 123_456_789n,
  credentialBlinding: 987_654_321n,
  dateOfBirth: "1990-04-03",
  nationality: "ARG",
  issuingState: "ARG",
  expiryDate: "2031-07-09",
  documentClass: "epassport" as const,
  assurance: "chip-auth" as const,
  issuedAtEpoch: 230,
};

const credentialFingerprint = zkPrivateCredentialFingerprint(credential);
assert.equal(
  credentialFingerprint,
  "0x5f3113cae53c94a863c5362d229137c767d996e444283541f19b13aac89e7f11",
  "private credential ABI fingerprint is pinned across languages",
);

const scope = {
  mode: "single-use" as const,
  chainId: 84532,
  verifier: "0x1111111111111111111111111111111111111111" as const,
  consumer: "0x2222222222222222222222222222222222222222" as const,
  context: keccak256(stringToBytes("membership:season-1")),
  policyHash,
};
const scopeHash: Hex = zkNullifierScopeHash(scope);
assert.equal(
  scopeHash,
  "0x6f9eb06ffea41fade00efe22ab9a7a855f366218cd9248acb84e7578a4f90716",
  "nullifier scope hash is pinned across languages",
);
const nullifierPreimage = zkScopedNullifierPreimage(credential.holderSecret, scope);
assert.deepEqual(
  nullifierPreimage.map(String),
  [
    "3753063511814324395807447140844095217",
    "39595397136107903161255285981469469429",
    "1",
    "123456789",
    "148368269012998052364797751201271282309",
    "126559033271166220203394870356863420182",
  ],
  "circuit nullifier preimage order is pinned",
);

const signalValues: ZkIdentityPublicSignalValues = {
  circuitId: keccak256(stringToBytes("circuit:v2-spike:1")),
  issuerKeyId,
  activeRoot: keccak256(stringToBytes("active-root:testnet:230")),
  policyHash,
  presentationBindingHash,
  nullifierScopeHash: scopeHash,
  scopedNullifier: 4_242_424_242n,
  subject: "0x3333333333333333333333333333333333333333" as const,
  result: true,
  credentialEpoch: 230,
  statusEpoch: 0,
};
const signals = encodeZkIdentityPublicSignals(signalValues);
assert.equal(signals.length, ZK_PUBLIC_SIGNAL_COUNT);
assert.deepEqual(
  signals.map(String),
  [
    "1",
    "148470164970938473527131569574145738248",
    "143106528634218877324650955020395841930",
    "3635849571425045330628617071914858755",
    "294515953839665300979725696144129953057",
    "56743338650715011814192789619580272247",
    "283811814910439300292750339907545096601",
    "84332592671497082657127333409566874930",
    "237646548228780080072226119388672926626",
    "335934530153236393154503107393022614242",
    "104498824908571987640421674469385365408",
    "148368269012998052364797751201271282309",
    "126559033271166220203394870356863420182",
    "4242424242",
    "292300327466180583640736966543256603931186508595",
    "1",
    "230",
    "0",
  ],
  "public-signal order is pinned across languages",
);
assert.deepEqual(decodeZkIdentityPublicSignals(signals), signalValues);
assert.equal(serializeZkIdentityPublicSignals(signals).length, 2 + 64 * ZK_PUBLIC_SIGNAL_COUNT);

const researchActiveRoot =
  "0x1f9cbf406714091dcdcc8ceaeecdcb56f0d50cead85493ac98d952b186bd70ef" as const;
const researchVerifier = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f" as const;
const researchConsumer = "0x2222222222222222222222222222222222222222" as const;
const researchSubject = "0x3333333333333333333333333333333333333333" as const;
const researchContext = keccak256(stringToBytes("membership:dynamic-status-fixture"));
const researchChallenge = keccak256(stringToBytes("challenge:dynamic-status-fixture"));
const researchRegistration = dynamicStatusPolicyRegistration({
  policy: {
    kind: "dynamic-status",
    status: "sanctions-clear",
    providerId: "self:ofac",
    listVersion: "research:fixture-1",
    statusRoot: researchActiveRoot,
    maximumAgeSeconds: 86_400,
  },
  publishedAt: 1_788_480_000,
});
assert.equal(
  researchRegistration.policyHash,
  "0x3263bf72679d2a1d55af03c9659ff646b70347e0bda15b50fbe11ad19ac338c9",
);
const researchBinding = zkPresentationBindingHash({
  policyHash: researchRegistration.policyHash,
  chainId: 84_532,
  verifier: researchVerifier,
  consumer: researchConsumer,
  subject: researchSubject,
  context: researchContext,
  challenge: researchChallenge,
  epoch: 230,
});
const researchScopeHash = zkNullifierScopeHash({
  mode: "single-use",
  chainId: 84_532,
  verifier: researchVerifier,
  consumer: researchConsumer,
  context: researchContext,
  policyHash: researchRegistration.policyHash,
});
const researchSignalValues: ZkIdentityPublicSignalValues = {
  circuitId: keccak256(stringToBytes("ubi2.zk-identity.v2.dynamic-status-packed-research-1")),
  issuerKeyId: joinBytes32(
    5_684_059_935_654_687_451_218_130_737_850_785_594n,
    67_299_010_049_198_418_576_218_540_330_172_003_346n,
  ),
  activeRoot: researchActiveRoot,
  policyHash: researchRegistration.policyHash,
  presentationBindingHash: researchBinding,
  nullifierScopeHash: researchScopeHash,
  scopedNullifier: 20_836_277_576_622_436_304_605_240_530_674_583_438_128_730_513_013_950_421_677_813_631_609_875_289_808n,
  subject: researchSubject,
  result: true,
  credentialEpoch: 230,
  statusEpoch: researchRegistration.publishedAt,
};
const researchSignals = encodeZkIdentityPublicSignals(researchSignalValues);
assert.deepEqual(
  researchSignals.map(String),
  [
    "1",
    "289702399193246464478010289331281785396",
    "48741886182628607789356429954167136159",
    "5684059935654687451218130737850785594",
    "67299010049198418576218540330172003346",
    "42019945222001701131111497448068860758",
    "320120940214504009201675825938958217455",
    "66979320182552521921400387039049807430",
    "243265757976093206830525462510393571529",
    "18413394222340233844127362083622107755",
    "139360669093465060426168882985392551801",
    "6847975291419670879861391421147823714",
    "88504934016337333378500625477300740379",
    "20836277576622436304605240530674583438128730513013950421677813631609875289808",
    "292300327466180583640736966543256603931186508595",
    "1",
    "230",
    "1788480000",
  ],
  "research proof public signals are pinned across SDK, circuit, and Solidity",
);
assert.deepEqual(decodeZkIdentityPublicSignals(researchSignals), researchSignalValues);

assert.equal(
  encodeZkPredicateProofContext({
    context: keccak256(stringToBytes("membership:season-1")),
    challenge: keccak256(stringToBytes("challenge-1")),
    nullifierMode: "single-use",
  }).length,
  2 + 64 * 3,
  "adapter context is one canonical three-word ABI tuple",
);
assert.throws(
  () =>
    encodeZkPredicateProofContext({
      context: keccak256(stringToBytes("membership:season-1")),
      challenge: `0x${"00".repeat(32)}`,
      nullifierMode: "single-use",
    }),
  /challenge must not be zero/u,
);

const [policyHigh, policyLow] = splitBytes32(policyHash);
assert.equal(joinBytes32(policyHigh, policyLow), policyHash, "bytes32 limb conversion is lossless");

assert.throws(
  () => encodeZkIdentityPublicSignals({ ...signalValues, scopedNullifier: BN254_SCALAR_FIELD }),
  /canonical BN254/,
);
assert.throws(
  () => decodeZkIdentityPublicSignals([...signals.slice(0, 15), 2n, ...signals.slice(16)]),
  /zero or one/,
);
assert.throws(
  () => zkPrivateCredentialFingerprint({ ...credential, nationality: "AR" }),
  /ISO alpha-3/,
);
assert.throws(
  () => zkPrivateCredentialFingerprint({ ...credential, holderSecret: 0n }),
  /non-zero canonical BN254/,
);
assert.throws(
  () => zkNullifierScopeHash({ ...scope, verifier: "0x0000000000000000000000000000000000000000" }),
  /zero address/,
);
assert.throws(
  () => decodeZkIdentityPublicSignals([...signals.slice(0, 14), 0n, ...signals.slice(15)]),
  /zero address/,
);

console.log("zk identity encoding: credential + nullifier + public-signal parity PASS");
