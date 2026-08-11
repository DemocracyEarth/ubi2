import assert from "node:assert/strict";
import { predicateContext, predicateDescriptor, predicateDescriptorHash } from "./predicate";

assert.equal(predicateDescriptor({ kind: "age", minimum: 18 }), "age>=18");
assert.equal(predicateDescriptor({ kind: "nationality", country: "arg" }), "nationality=ARG");
assert.equal(predicateDescriptor({ kind: "sanctions" }), "sanctions-clear");

assert.equal(
  predicateDescriptorHash("age>=18"),
  "0xe3e8342a70f40c3ef2dacba55a24b87789c9ddaf64d9d329e304d6478e856e96",
);
assert.equal(
  predicateDescriptorHash("sanctions-clear"),
  "0xd414ccab0db9191e8802a047b1c0f135d0d054ed112952854cd54456966c47da",
);
assert.throws(() => predicateDescriptorHash("age >= 18"));
assert.throws(() => predicateDescriptorHash("nationality=arg"));
assert.match(predicateContext("community:season-1"), /^0x[0-9a-f]{64}$/);

console.log("predicate SDK: descriptor + context vectors PASS");
