interface ExpiringEntry<T> {
  value: T;
  expiresAt: number;
}

/**
 * Small in-memory TTL store used by the single-worker verification handoff.
 * Updates deliberately preserve the original expiry: a refreshed authorization
 * must never extend the lifetime of the passport verification that created it.
 */
export class ExpiringStore<T> {
  private readonly entries = new Map<string, ExpiringEntry<T>>();

  constructor(
    private readonly maxEntries: number,
    private readonly now: () => number = Date.now,
  ) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0) {
      throw new Error("ExpiringStore maxEntries must be a positive integer.");
    }
  }

  set(key: string, value: T, expiresAt: number): void {
    const now = this.now();
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) {
      throw new Error("ExpiringStore expiry must be a future Unix timestamp in milliseconds.");
    }

    this.prune(now);
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAt });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (!oldest) break;
      this.entries.delete(oldest);
    }
  }

  get(key: string): T | null {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return null;
    }
    return entry.value;
  }

  update(key: string, value: T): boolean {
    const entry = this.entries.get(key);
    if (!entry) return false;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return false;
    }
    entry.value = value;
    return true;
  }

  delete(key: string): void {
    this.entries.delete(key);
  }

  private prune(now: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }
}
