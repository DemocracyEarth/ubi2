import assert from "node:assert/strict";
import {
  decodeDisclosureProfile,
  decodeDisclosureRequest,
  encodeDisclosureProfile,
  encodeDisclosureRequest,
  verificationConfigFor,
  type DisclosureProfile,
} from "../app/lib/disclosure-profile";
import { evalPredicate, nationalityToBytes3 } from "../app/lib/predicate";
import { predicateDescriptorHash } from "@ubi2/sdk";
import { CHAINS, isPredicateDeployed } from "../app/config";

for (const profile of [
  { age: null, nationality: false },
  { age: 18, nationality: false },
  { age: 21, nationality: true },
] satisfies DisclosureProfile[]) {
  const encoded = encodeDisclosureProfile(profile);
  assert.deepEqual(decodeDisclosureProfile(encoded), profile);
  assert.deepEqual(decodeDisclosureProfile(Buffer.from(encoded).toString("hex")), profile);
  const request = encodeDisclosureRequest(profile, "0123456789abcdef0123456789abcdef");
  assert.deepEqual(decodeDisclosureRequest(request), {
    profile,
    session: "0123456789abcdef0123456789abcdef",
  });
  assert.deepEqual(decodeDisclosureRequest(Buffer.from(request).toString("hex")), {
    profile,
    session: "0123456789abcdef0123456789abcdef",
  });
}

assert.equal(decodeDisclosureProfile("poh-predicates-v1:19:1"), null);
assert.equal(decodeDisclosureRequest("poh-predicates-v1:18:1:guessable"), null);
assert.deepEqual(verificationConfigFor({ age: 21, nationality: true }), { minimumAge: 21, ofac: true });
assert.deepEqual(verificationConfigFor({ age: null, nationality: false }), { ofac: true });

const attributes = { ageFlags: 3, nationality: nationalityToBytes3("ARG"), ofacClear: true };
assert.equal(evalPredicate("age>=18", attributes), true);
assert.equal(evalPredicate("age>=21", attributes), true);
assert.equal(evalPredicate("nationality=ARG", attributes), true);
assert.equal(evalPredicate("sanctions-clear", attributes), true);
assert.throws(() => evalPredicate("nationality=arg", attributes));

assert.equal(predicateDescriptorHash("age>=18"), "0xe3e8342a70f40c3ef2dacba55a24b87789c9ddaf64d9d329e304d6478e856e96");

const ethereumSepolia = CHAINS.find((chain) => chain.chainId === 11155111);
const baseSepolia = CHAINS.find((chain) => chain.chainId === 84532);
const robinhoodTestnet = CHAINS.find((chain) => chain.chainId === 46630);
const ethereumMainnet = CHAINS.find((chain) => chain.chainId === 1);
assert.ok(ethereumSepolia && isPredicateDeployed(ethereumSepolia));
assert.ok(baseSepolia && isPredicateDeployed(baseSepolia));
assert.ok(robinhoodTestnet && isPredicateDeployed(robinhoodTestnet));
assert.ok(ethereumMainnet && !isPredicateDeployed(ethereumMainnet));

console.log("predicate product: disclosure profiles + canonical evaluation + deployment registry PASS");
