import type { Request, Response, NextFunction } from 'express';

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export interface RateLimiterOptions {
  windowMs: number;
  maxRequests: number;
  maxKeys?: number;
  scope?: string;
  keyGenerator?: (req: Request) => string;
  message?: string;
}

export interface BoundedRateLimiterMiddleware {
  (req: Request, res: Response, next: NextFunction): void;
  getStoreSize: () => number;
  pruneExpired: (now?: number) => number;
  clear: () => void;
}

export function normalizeClientIp(req: Pick<Request, 'ip' | 'socket'>): string {
  const raw = req.ip || req.socket?.remoteAddress || 'unknown';
  return String(raw).trim().toLowerCase().slice(0, 128) || 'unknown';
}

/**
 * Bounded, self-pruning rate limiter middleware.
 * Prevents unbounded memory growth under high-cardinality IP or path floods
 * by sweeping expired entries and evicting oldest keys when maxKeys is reached.
 */
export function createBoundedRateLimiter(
  options: RateLimiterOptions
): BoundedRateLimiterMiddleware {
  const windowMs = Math.max(1000, options.windowMs);
  const maxRequests = Math.max(1, options.maxRequests);
  const maxKeys = Math.max(10, options.maxKeys ?? 5000);
  const scope = options.scope || 'default';
  const errorMessage =
    options.message || 'Too many requests. Please wait a moment and try again.';

  const store = new Map<string, RateLimitEntry>();
  let lastSweepAt = Date.now();
  const sweepIntervalMs = Math.min(windowMs, 30_000);

  function pruneExpired(now = Date.now()): number {
    let removed = 0;
    for (const [k, entry] of store.entries()) {
      if (now >= entry.resetAt) {
        store.delete(k);
        removed++;
      }
    }
    lastSweepAt = now;
    return removed;
  }

  function ensureBoundedCapacity(now: number): void {
    if (store.size < maxKeys) return;
    pruneExpired(now);
    if (store.size < maxKeys) return;

    // Map iterates in insertion order; evict oldest entries until below maxKeys
    const toEvict = store.size - maxKeys + 1;
    let evicted = 0;
    for (const oldestKey of store.keys()) {
      store.delete(oldestKey);
      evicted++;
      if (evicted >= toEvict) break;
    }
  }

  const middleware = ((req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    if (now - lastSweepAt >= sweepIntervalMs) {
      pruneExpired(now);
    }

    const customPart = options.keyGenerator
      ? options.keyGenerator(req)
      : `${normalizeClientIp(req)}:${req.baseUrl || ''}${req.path || ''}`;
    const key = `${scope}:${customPart.slice(0, 256)}`;

    const existing = store.get(key);
    if (!existing || now >= existing.resetAt) {
      if (existing) {
        store.delete(key);
      }
      ensureBoundedCapacity(now);
      const resetAt = now + windowMs;
      store.set(key, { count: 1, resetAt });
      res.setHeader('X-RateLimit-Limit', String(maxRequests));
      res.setHeader('X-RateLimit-Remaining', String(Math.max(0, maxRequests - 1)));
      res.setHeader('X-RateLimit-Reset', String(Math.ceil(resetAt / 1000)));
      return next();
    }

    if (existing.count >= maxRequests) {
      const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      res.setHeader('X-RateLimit-Limit', String(maxRequests));
      res.setHeader('X-RateLimit-Remaining', '0');
      res.setHeader('X-RateLimit-Reset', String(Math.ceil(existing.resetAt / 1000)));
      return res.status(429).json({
        error: errorMessage,
        retryAfterSeconds,
      });
    }

    existing.count += 1;
    res.setHeader('X-RateLimit-Limit', String(maxRequests));
    res.setHeader(
      'X-RateLimit-Remaining',
      String(Math.max(0, maxRequests - existing.count))
    );
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(existing.resetAt / 1000)));
    return next();
  }) as BoundedRateLimiterMiddleware;

  middleware.getStoreSize = () => store.size;
  middleware.pruneExpired = pruneExpired;
  middleware.clear = () => store.clear();

  return middleware;
}
