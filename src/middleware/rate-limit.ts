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
  trustProxy?: boolean | number;
  keyGenerator?: (req: Request) => string;
  message?: string;
}

export interface BoundedRateLimiterMiddleware {
  (req: Request, res: Response, next: NextFunction): void;
  getStoreSize: () => number;
  pruneExpired: (now?: number) => number;
  clear: () => void;
}

/**
 * Resolves a safe Express `trust proxy` configuration.
 * Never returns unconditional `true` (which would trust arbitrary client-supplied X-Forwarded-For chains).
 * Defaults to 1 hop on Cloud Run / production reverse proxy deployments and false when direct,
 * or honors explicit TRUST_PROXY_HOPS ('0'/'false' -> false, positive integer -> hop count).
 */
export function resolveTrustProxyConfig(
  rawEnvOrMap:
    | string
    | Record<string, string | undefined>
    | undefined = process.env.TRUST_PROXY_HOPS ?? process.env.TRUST_PROXY,
  nodeEnv: string | undefined = process.env.NODE_ENV,
  isCloudRun: boolean = Boolean(process.env.K_SERVICE)
): boolean | number {
  const rawEnvValue =
    typeof rawEnvOrMap === 'object' && rawEnvOrMap !== null
      ? rawEnvOrMap.TRUST_PROXY_HOPS ?? rawEnvOrMap.TRUST_PROXY
      : rawEnvOrMap;

  if (typeof rawEnvValue === 'string' && rawEnvValue.trim() !== '') {
    const cleaned = rawEnvValue.trim().toLowerCase();
    if (cleaned === 'false' || cleaned === '0' || cleaned === 'off' || cleaned === 'none') {
      return false;
    }
    if (cleaned === 'true') {
      return 1;
    }
    const parsed = Number.parseInt(cleaned, 10);
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 10) {
      return parsed;
    }
  }
  return isCloudRun || nodeEnv === 'production' ? 1 : false;
}

/**
 * Normalizes the client IP address for rate-limiting without ever trusting raw client-supplied
 * X-Forwarded-For headers directly.
 * - When proxy trust is disabled (`trustProxy === false`), strictly uses `req.socket.remoteAddress`.
 * - When proxy trust is enabled to a fixed hop count in Express (`app.set('trust proxy', N)`),
 *   uses `req.ip` (computed by Express from the trusted rightmost proxy hop) with fallback to `req.socket.remoteAddress`.
 */
export function normalizeClientIp(
  req: Pick<Request, 'ip' | 'socket'> & {
    app?: { get?: (setting: string) => unknown };
    headers?: Record<string, unknown>;
  },
  options?: { trustProxy?: boolean | number }
): string {
  const appTrustProxy =
    options?.trustProxy !== undefined
      ? options.trustProxy
      : typeof req.app?.get === 'function'
      ? req.app.get('trust proxy')
      : undefined;

  const rawIp =
    appTrustProxy === false
      ? req.socket?.remoteAddress || req.ip || 'unknown'
      : req.ip || req.socket?.remoteAddress || 'unknown';

  let normalized = String(rawIp).trim().toLowerCase();
  if (normalized.startsWith('::ffff:')) {
    normalized = normalized.slice('::ffff:'.length);
  }
  return normalized.slice(0, 128) || 'unknown';
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
      : `${normalizeClientIp(req, { trustProxy: options.trustProxy })}:${req.baseUrl || ''}${req.path || ''}`;
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
