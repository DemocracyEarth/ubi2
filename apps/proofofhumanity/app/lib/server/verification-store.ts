import "server-only";

import { ExpiringStore } from "../expiring-store";
import { FixedWindowRateLimiter } from "../fixed-window-rate-limit";

export const VERIFICATION_RECORD_TTL_MS = 10 * 60 * 1_000;
const MAX_RECORDS = 5_000;

const processState = globalThis as typeof globalThis & {
  __pohVerificationRecords?: ExpiringStore<unknown>;
  __pohRateLimiter?: FixedWindowRateLimiter;
};

const records =
  processState.__pohVerificationRecords instanceof ExpiringStore
    ? processState.__pohVerificationRecords
    : (processState.__pohVerificationRecords = new ExpiringStore(MAX_RECORDS));
const limiter = (processState.__pohRateLimiter ??= new FixedWindowRateLimiter(20_000));

function recordKey(address: string, session: string): string {
  if (!/^[0-9a-f]{32}$/.test(session)) throw new Error("Invalid verification session.");
  return `poh:verification:v1:${address.toLowerCase()}:${session}`;
}

/**
 * Short-lived handoff between Self's mobile callback and browser polling. It is deliberately
 * bounded and contains no raw passport proof. Production must run this route as one sticky Node
 * service; use a reviewed shared-store adapter before introducing multiple replicas.
 */
export function setVerificationRecord<T>(
  address: string,
  session: string,
  value: T,
  expiresAt = Date.now() + VERIFICATION_RECORD_TTL_MS,
): void {
  const now = Date.now();
  if (
    !Number.isSafeInteger(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + VERIFICATION_RECORD_TTL_MS
  ) {
    throw new Error("Verification record expiry must be within the next ten minutes.");
  }
  records.set(recordKey(address, session), value, expiresAt);
}

export function getVerificationRecord<T>(address: string, session: string): T | null {
  return records.get(recordKey(address, session)) as T | null;
}

/** Replace a live value without moving its original proof-verification expiry. */
export function updateVerificationRecord<T>(address: string, session: string, value: T): boolean {
  return records.update(recordKey(address, session), value);
}

/**
 * Atomically replace a live value only when it is still the exact record previously read.
 * JavaScript runs this read/compare/write section without an await, so concurrent handlers cannot
 * both claim the same verification record before one of them publishes its submitting state.
 */
export function compareAndUpdateVerificationRecord<T>(
  address: string,
  session: string,
  expected: T,
  value: T,
): boolean {
  const key = recordKey(address, session);
  if (records.get(key) !== expected) return false;
  return records.update(key, value);
}

export function deleteVerificationRecord(address: string, session: string): void {
  records.delete(recordKey(address, session));
}

export function rateLimit(
  scope: string,
  identity: string,
  limit: number,
  windowSeconds: number,
): { allowed: boolean; retryAfter: number } {
  return limiter.take(scope, identity, limit, windowSeconds);
}
