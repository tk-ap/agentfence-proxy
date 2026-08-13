'use strict';

/**
 * In-memory sliding-window rate limiter, keyed by whatever the caller
 * passes (normally client IP). Deliberately simple — fine for a single
 * Render instance fronting a marketing-site demo widget; a real
 * multi-instance deployment would need a shared store (Redis) instead.
 */
class RateLimiter {
  constructor({ windowMs = 60_000, max = 20 } = {}) {
    this.windowMs = windowMs;
    this.max = max;
    this.hits = new Map(); // key -> array of timestamps within the window
  }

  check(key) {
    const now = Date.now();
    const recent = (this.hits.get(key) || []).filter((t) => now - t < this.windowMs);
    if (recent.length >= this.max) {
      const retryAfterMs = this.windowMs - (now - recent[0]);
      this.hits.set(key, recent);
      return { allowed: false, retryAfterMs: Math.max(retryAfterMs, 0) };
    }
    recent.push(now);
    this.hits.set(key, recent);
    return { allowed: true, remaining: this.max - recent.length };
  }

  /** Drops keys with no hits inside the current window — bounds memory across many distinct IPs over time. Call periodically, not per-request. */
  sweep() {
    const now = Date.now();
    for (const [key, arr] of this.hits.entries()) {
      const fresh = arr.filter((t) => now - t < this.windowMs);
      if (fresh.length === 0) this.hits.delete(key);
      else this.hits.set(key, fresh);
    }
  }
}

module.exports = { RateLimiter };
