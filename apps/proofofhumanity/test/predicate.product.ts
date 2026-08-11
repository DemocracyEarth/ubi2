import assert from "node:assert/strict";
import {
  decodeDisclosureProfile,
  decodeDisclosureRequest,
  encodeDisclosureProfile,
  encodeDisclosureRequest,
  verificationConfigFor,
  type DisclosureProfile,
} from "../app/lib/disclosure-profile";
import { COUNTRIES, countryByAlpha3, searchCountries } from "../app/lib/countries";
import { evalPredicate, nationalityToBytes3 } from "../app/lib/predicate";
import {
  verificationGuidance,
  type VerificationStateInput,
} from "../app/predicates/verify-state";
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

assert.equal(COUNTRIES.length, 249);
assert.equal(new Set(COUNTRIES.map((country) => country.alpha2)).size, 249);
assert.equal(new Set(COUNTRIES.map((country) => country.alpha3)).size, 249);
assert.deepEqual(countryByAlpha3("arg"), {
  alpha2: "AR",
  alpha3: "ARG",
  flag: "🇦🇷",
  name: "Argentina",
  search: "argentina ar arg",
});
assert.equal(countryByAlpha3("XKK"), null);
assert.equal(searchCountries("arg")[0]?.alpha3, "ARG");
assert.equal(searchCountries("united sta").some((country) => country.alpha3 === "USA"), true);
assert.equal(searchCountries("deu")[0]?.name, "Germany");

const readyState: VerificationStateInput = {
  accountConnected: true,
  chainName: "Base Sepolia",
  chainState: "ready",
  claimAvailable: true,
  consumerValid: true,
  contextValid: true,
  countrySelected: true,
  hasCredential: true,
  nationalitySelected: false,
};
const guidance = (overrides: Partial<VerificationStateInput>) =>
  verificationGuidance({ ...readyState, ...overrides });

assert.equal(guidance({ hasCredential: false }).eyebrow, "Step 1 of 3");
assert.equal(guidance({ claimAvailable: false }).eyebrow, "Claim not prepared");
assert.equal(guidance({ accountConnected: false }).eyebrow, "Step 2 of 3");
assert.equal(guidance({ chainState: "checking" }).eyebrow, "Checking contract");
assert.equal(guidance({ chainState: "missing" }).eyebrow, "Mint required");
assert.equal(guidance({ chainState: "wrong-owner" }).eyebrow, "Wallet mismatch");
assert.equal(guidance({ chainState: "expired" }).eyebrow, "Credential expired");
assert.equal(guidance({ chainState: "unavailable" }).eyebrow, "Network unavailable");
assert.equal(guidance({ nationalitySelected: true, countrySelected: false }).title, "Choose a country");
assert.equal(guidance({ contextValid: false }).title, "Name this verification context");
assert.equal(guidance({ consumerValid: false }).title, "Enter the receiving app or contract");
assert.equal(guidance({}).canIssue, true);

const ethereumSepolia = CHAINS.find((chain) => chain.chainId === 11155111);
const baseSepolia = CHAINS.find((chain) => chain.chainId === 84532);
const celoSepolia = CHAINS.find((chain) => chain.chainId === 11142220);
const worldSepolia = CHAINS.find((chain) => chain.chainId === 4801);
const robinhoodTestnet = CHAINS.find((chain) => chain.chainId === 46630);
const ethereumMainnet = CHAINS.find((chain) => chain.chainId === 1);
assert.ok(ethereumSepolia && isPredicateDeployed(ethereumSepolia));
assert.ok(baseSepolia && isPredicateDeployed(baseSepolia));
assert.ok(celoSepolia && isPredicateDeployed(celoSepolia));
assert.ok(worldSepolia && isPredicateDeployed(worldSepolia));
assert.ok(robinhoodTestnet && isPredicateDeployed(robinhoodTestnet));
assert.ok(ethereumMainnet && !isPredicateDeployed(ethereumMainnet));

console.log("predicate product: disclosures + country selector + guidance + deployments PASS");
