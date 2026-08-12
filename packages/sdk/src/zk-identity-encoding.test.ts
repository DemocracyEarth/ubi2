import assert from "node:assert/strict";
import { keccak256, stringToBytes, type Hex } from "viem";
import {
  BN254_SCALAR_FIELD,
  decodeZkIdentityPublicSignals,
  encodeZkIdentityPublicSignals,
  joinBytes32,
  serializeZkIdentityPublicSignals,
  splitBytes32,
  zkNullifierScopeHash,
  zkPrivateCredentialFingerprint,
  zkScopedNullifierPreimage,
  ZK_PUBLIC_SIGNAL_COUNT,
  type ZkIdentityPublicSignalValues,
} from "./zk-identity-encoding";

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
