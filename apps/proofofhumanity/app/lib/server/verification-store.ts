import "server-only";

const RECORD_TTL_MS = 10 * 60 * 1_000;
const MAX_RECORDS = 5_000;

interface StoredValue {
  value: unknown;
  expiresAt: number;
}

interface LimitValue {
  count: number;
  expiresAt: number;
}

const processState = globalThis as typeof globalThis & {
  __pohVerificationRecords?: Map<string, StoredValue>;
  __pohRateLimits?: Map<string, LimitValue>;
};

const records = (processState.__pohVerificationRecords ??= new Map());
const limits = (processState.__pohRateLimits ??= new Map());

function recordKey(address: string, session: string): string {
  if (!/^[0-9a-f]{32}$/.test(session)) throw new Error("Invalid verification session.");
  return `poh:verification:v1:${address.toLowerCase()}:${session}`;
}

function prune<T extends { expiresAt: number }>(map: Map<string, T>, max: number): void {
  const now = Date.now();
  for (const [key, entry] of map) {
    if (entry.expiresAt <= now) map.delete(key);
  }
  while (map.size >= max) {
    const oldest = map.keys().next().value as string | undefined;
    if (!oldest) break;
    map.delete(oldest);
  }
}

/**
 * Short-lived handoff between Self's mobile callback and browser polling. It is deliberately
 * bounded and contains no raw passport proof. Production must run this route as one sticky Node
 * service; use a reviewed shared-store adapter before introducing multiple replicas.
 */
export function setVerificationRecord<T>(address: string, session: string, value: T): void {
  prune(records, MAX_RECORDS);
  records.set(recordKey(address, session), { value, expiresAt: Date.now() + RECORD_TTL_MS });
}

export function getVerificationRecord<T>(address: string, session: string): T | null {
  const key = recordKey(address, session);
  const entry = records.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    records.delete(key);
    return null;
  }
  return entry.value as T;
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
  prune(limits, 20_000);
  const safeIdentity = identity.toLowerCase().replace(/[^a-z0-9:._-]/g, "").slice(0, 160) || "unknown";
  const windowMs = windowSeconds * 1_000;
  const window = Math.floor(Date.now() / windowMs);
  const key = `poh:limit:${scope}:${safeIdentity}:${window}`;
  const expiresAt = (window + 1) * windowMs;
  const entry = limits.get(key);
  const count = entry ? entry.count + 1 : 1;
  limits.set(key, { count, expiresAt });
  return { allowed: count <= limit, retryAfter: Math.max(1, Math.ceil((expiresAt - Date.now()) / 1_000)) };
}
