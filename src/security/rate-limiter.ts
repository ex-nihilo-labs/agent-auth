import { Database } from "bun:sqlite";

/**
 * Token-bucket rate limiter backed by SQLite.
 * Persists across restarts (per security review).
 *
 * Default limits (from Cerberus pattern):
 * - 3 requests per minute
 * - 20 requests per hour
 */

interface RateLimit {
  maxRequests: number;
  windowSeconds: number;
}

const LIMITS: Record<string, RateLimit> = {
  per_minute: { maxRequests: 3, windowSeconds: 60 },
  per_hour: { maxRequests: 20, windowSeconds: 3600 },
};

export class RateLimiter {
  private db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  /**
   * Check if a request is allowed. Returns true if within limits.
   * Automatically increments counters.
   */
  check(key: string = "global"): { allowed: boolean; retryAfter?: number } {
    const now = Math.floor(Date.now() / 1000);

    for (const [limitName, limit] of Object.entries(LIMITS)) {
      const rateKey = `${key}:${limitName}`;

      const row = this.db
        .query("SELECT count, window_start FROM rate_limits WHERE key = ?")
        .get(rateKey) as { count: number; window_start: number } | null;

      if (!row || now - row.window_start >= limit.windowSeconds) {
        // Window expired — reset
        this.db.run(
          "INSERT OR REPLACE INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)",
          [rateKey, now]
        );
        continue;
      }

      if (row.count >= limit.maxRequests) {
        const retryAfter = limit.windowSeconds - (now - row.window_start);
        return { allowed: false, retryAfter };
      }

      this.db.run(
        "UPDATE rate_limits SET count = count + 1 WHERE key = ?",
        [rateKey]
      );
    }

    return { allowed: true };
  }
}
