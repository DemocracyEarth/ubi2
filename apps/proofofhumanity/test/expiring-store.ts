import { ExpiringStore } from "../app/lib/expiring-store";
import { publicRelayRecord, type RelayRecord } from "../app/lib/verification-record";

let now = 1_000;
const store = new ExpiringStore<string>(2, () => now);

function assertEqual<T>(actual: T, expected: T, message: string): void {
  if (actual !== expected) {
    throw new Error(`${message}: got ${String(actual)}, want ${String(expected)}`);
  }
  console.log(`  ✓ ${message}`);
}

console.log("\n=== verification handoff expiry ===\n");

store.set("verified", "authorization-1", 2_000);
now = 1_500;
assertEqual(store.update("verified", "authorization-2"), true, "a live authorization can refresh");
assertEqual(store.get("verified"), "authorization-2", "refresh replaces only the stored value");

now = 2_000;
assertEqual(store.get("verified"), null, "refresh preserves the original verification expiry");
assertEqual(store.update("verified", "authorization-3"), false, "an expired grant cannot be revived");

now = 3_000;
store.set("oldest", "one", 4_000);
store.set("newer", "two", 4_000);
store.set("newest", "three", 4_000);
assertEqual(store.get("oldest"), null, "bounded storage evicts its oldest live capability");
assertEqual(store.get("newer"), "two", "bounded storage retains newer live capabilities");
assertEqual(store.get("newest"), "three", "bounded storage retains the newest capability");

let invalidExpiryRejected = false;
try {
  store.set("invalid", "value", now);
} catch {
  invalidExpiryRejected = true;
}
assertEqual(invalidExpiryRejected, true, "non-future expiries fail closed");

const privateRecord = {
  status: "ready",
  zkIssuanceGrant: {
    subject: "0x1111111111111111111111111111111111111111",
    duplicateKey: `0x${"22".repeat(32)}`,
    credentialCommitment: 123n,
    chainId: 1,
    registry: "0x3333333333333333333333333333333333333333",
    bridge: "0x4444444444444444444444444444444444444444",
    issuerKeyId: `0x${"55".repeat(32)}`,
    selfConfigId: `0x${"66".repeat(32)}`,
    expiresAtMs: 9_999,
  },
  receivedAt: 1_000,
} as RelayRecord;
const publicRecord = publicRelayRecord(privateRecord);
assertEqual(
  "zkIssuanceGrant" in publicRecord,
  false,
  "the proof-derived refresh grant is omitted from API records",
);
assertEqual(
  JSON.stringify(publicRecord),
  '{"status":"ready","receivedAt":1000}',
  "the public record remains JSON-safe even though the private grant contains bigint",
);
