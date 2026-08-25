interface LimitValue {
  count: number;
  expiresAt: number;
}

/** Small deterministic fixed-window limiter used behind a trusted single-process proxy. */
export class FixedWindowRateLimiter {
  private readonly limits = new Map<string, LimitValue>();

  constructor(
    private readonly maxEntries: number,
    private readonly now: () => number = Date.now,
  ) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0) {
      throw new Error("Rate limiter maxEntries must be a positive integer.");
    }
  }

  take(
    scope: string,
    identity: string,
    limit: number,
    windowSeconds: number,
  ): { allowed: boolean; retryAfter: number } {
    if (!Number.isSafeInteger(limit) || limit <= 0 || !Number.isSafeInteger(windowSeconds) || windowSeconds <= 0) {
      throw new Error("Rate limit and window must be positive integers.");
    }
    const now = this.now();
    this.prune(now);
    const safeScope = scope.toLowerCase().replace(/[^a-z0-9:._-]/g, "").slice(0, 80) || "unknown";
    const safeIdentity = identity.toLowerCase().replace(/[^a-z0-9:._-]/g, "").slice(0, 160) || "unknown";
    const windowMs = windowSeconds * 1_000;
    const window = Math.floor(now / windowMs);
    const key = `poh:limit:${safeScope}:${safeIdentity}:${window}`;
    const expiresAt = (window + 1) * windowMs;
    const entry = this.limits.get(key);
    if (!entry && this.limits.size >= this.maxEntries) {
      let earliestExpiry = expiresAt;
      for (const value of this.limits.values()) {
        if (value.expiresAt < earliestExpiry) earliestExpiry = value.expiresAt;
      }
      return {
        allowed: false,
        retryAfter: Math.max(1, Math.ceil((earliestExpiry - now) / 1_000)),
      };
    }
    const count = entry ? entry.count + 1 : 1;
    this.limits.set(key, { count, expiresAt });
    return { allowed: count <= limit, retryAfter: Math.max(1, Math.ceil((expiresAt - now) / 1_000)) };
  }

  private prune(now: number): void {
    for (const [key, entry] of this.limits) {
      if (entry.expiresAt <= now) this.limits.delete(key);
    }
  }
}
