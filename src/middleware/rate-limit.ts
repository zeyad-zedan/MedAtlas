import type { Request, Response, NextFunction } from 'express';
import { sql } from 'drizzle-orm';
import { db, isDatabaseConfigured } from '../db/index.ts';

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export interface RateLimitConsumeResult {
  allowed: boolean;
  count: number;
  resetAt: number;
  maxRequests: number;
}

export interface SharedRateLimitStore {
  consume(params: {
    key: string;
    scope: string;
    windowMs: number;
    maxRequests: number;
    maxKeys: number;
    nowMs?: number;
  }): Promise<RateLimitConsumeResult>;
  pruneExpired?(nowMs?: number): Promise<number>;
  clear?(scope?: string): Promise<void>;
}

export interface SecondaryRateLimitRule {
  name?: string;
  scopeSuffix?: string;
  maxRequests: number;
  windowMs?: number;
  keyGenerator: (req: Request) => string | null | undefined;
}

export interface RateLimiterOptions {
  windowMs: number;
  maxRequests: number;
  maxKeys?: number;
  scope?: string;
  trustProxy?: boolean | number;
  keyGenerator?: (req: Request) => string;
  secondaryRules?: SecondaryRateLimitRule[];
  sharedStore?: SharedRateLimitStore | null;
  store?: SharedRateLimitStore | null;
  degradedModePolicy?: 'memory_fallback' | 'fail_closed';
  message?: string;
}

export interface BoundedRateLimiterMiddleware {
  (req: Request, res: Response, next: NextFunction): void | Promise<void>;
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
 * Creates a PostgreSQL-backed shared rate-limit store (`rate_limit_buckets` table)
 * that enforces atomic counters across multiple server instances and container restarts,
 * while protecting active multi-hit security counters (`count > 1`) from high-cardinality key churn.
 */
export function createPostgresRateLimitStore(): SharedRateLimitStore {
  let lastPruneMs = 0;

  return {
    async consume({ key, scope, windowMs, maxRequests, maxKeys, nowMs }) {
      const now = nowMs ?? Date.now();
      const nowDate = new Date(now);
      const nextResetDate = new Date(now + windowMs);

      // Periodically prune expired rows in the database
      if (now - lastPruneMs >= 15_000) {
        lastPruneMs = now;
        await db.execute(
          sql`DELETE FROM rate_limit_buckets WHERE reset_at <= ${nowDate}`
        ).catch(() => {});
      }

      // Check if key already exists and is active
      const existingRes = await db.execute(
        sql`SELECT count, reset_at FROM rate_limit_buckets WHERE key = ${key} LIMIT 1`
      );
      const existingRow = (existingRes as any).rows?.[0];

      if (!existingRow || new Date(existingRow.reset_at).getTime() <= now) {
        // Key is new or expired; check capacity in scope before inserting
        const countRes = await db.execute(
          sql`SELECT COUNT(*)::int AS cnt FROM rate_limit_buckets WHERE scope = ${scope} AND reset_at > ${nowDate}`
        );
        const activeInScope = Number((countRes as any).rows?.[0]?.cnt ?? 0);

        if (activeInScope >= maxKeys) {
          // Prune expired first
          await db.execute(
            sql`DELETE FROM rate_limit_buckets WHERE scope = ${scope} AND reset_at <= ${nowDate}`
          );

          // Evict only oldest single-hit probe keys (count = 1); NEVER evict active security counters (count > 1)
          const evictRes = await db.execute(
            sql`DELETE FROM rate_limit_buckets
                WHERE key IN (
                  SELECT key FROM rate_limit_buckets
                  WHERE scope = ${scope} AND count <= 1
                  ORDER BY updated_at ASC
                  LIMIT ${Math.max(1, activeInScope - maxKeys + 1)}
                )
                RETURNING key`
          );
          const evictedCount = Array.isArray((evictRes as any).rows)
            ? (evictRes as any).rows.length
            : 0;

          if (evictedCount === 0) {
            const recheckRes = await db.execute(
              sql`SELECT COUNT(*)::int AS cnt FROM rate_limit_buckets WHERE scope = ${scope} AND reset_at > ${nowDate}`
            );
            if (Number((recheckRes as any).rows?.[0]?.cnt ?? 0) >= maxKeys) {
              // Fail closed under saturation so active multi-hit blocks cannot be evicted
              return {
                allowed: false,
                count: maxRequests + 1,
                resetAt: now + windowMs,
                maxRequests,
              };
            }
          }
        }
      }

      // Atomic upsert in PostgreSQL across all instances
      const upsertRes = await db.execute(
        sql`INSERT INTO rate_limit_buckets (key, scope, count, reset_at, updated_at)
            VALUES (${key}, ${scope}, 1, ${nextResetDate}, ${nowDate})
            ON CONFLICT (key) DO UPDATE
            SET count = CASE
                  WHEN rate_limit_buckets.reset_at <= ${nowDate} THEN 1
                  ELSE rate_limit_buckets.count + 1
                END,
                reset_at = CASE
                  WHEN rate_limit_buckets.reset_at <= ${nowDate} THEN ${nextResetDate}
                  ELSE rate_limit_buckets.reset_at
                END,
                updated_at = ${nowDate}
            RETURNING count, reset_at`
      );

      const row = (upsertRes as any).rows?.[0];
      const count = Number(row?.count ?? 1);
      const resetAt = row?.reset_at ? new Date(row.reset_at).getTime() : now + windowMs;

      return {
        allowed: count <= maxRequests,
        count,
        resetAt,
        maxRequests,
      };
    },

    async pruneExpired(nowMs = Date.now()) {
      const nowDate = new Date(nowMs);
      const res = await db.execute(
        sql`DELETE FROM rate_limit_buckets WHERE reset_at <= ${nowDate} RETURNING key`
      );
      return Array.isArray((res as any).rows) ? (res as any).rows.length : 0;
    },

    async clear(scope?: string) {
      if (scope) {
        await db.execute(sql`DELETE FROM rate_limit_buckets WHERE scope = ${scope}`);
      } else {
        await db.execute(sql`DELETE FROM rate_limit_buckets`);
      }
    },
  };
}

export interface RateLimitStoreResolution {
  store: SharedRateLimitStore | undefined;
  type: 'shared_postgres' | 'memory_fallback' | 'memory_local';
  degradedModePolicy: 'memory_fallback' | 'fail_closed';
  warning?: string;
}

/**
 * Resolves the rate-limit store configuration using the actual configured database connection.
 * - Detects PostgreSQL availability via `isDatabaseConfigured(env)` (supports SQL_HOST/SQL_USER/... and DATABASE_URL).
 * - Enforces documented degraded policy: in production, if shared store is unavailable, falls back to memory with a
 *   deliberate alert and sets degradedModePolicy to fail_closed (or configurable via RATE_LIMIT_DEGRADED_POLICY).
 * - Never silently claims multi-instance protection when using in-memory storage.
 */
export function resolveRateLimitStoreConfig(
  env: NodeJS.ProcessEnv = process.env
): RateLimitStoreResolution {
  const isDbAvailable = isDatabaseConfigured(env);
  const isProd = env.NODE_ENV === 'production';
  const degradedModePolicy: 'memory_fallback' | 'fail_closed' =
    env.RATE_LIMIT_DEGRADED_POLICY === 'fail_closed'
      ? 'fail_closed'
      : env.RATE_LIMIT_DEGRADED_POLICY === 'memory_fallback'
      ? 'memory_fallback'
      : isProd
      ? 'fail_closed'
      : 'memory_fallback';

  if (isDbAvailable) {
    return {
      store: createPostgresRateLimitStore(),
      type: 'shared_postgres',
      degradedModePolicy,
    };
  }

  if (isProd) {
    const warning =
      degradedModePolicy === 'fail_closed'
        ? '[SECURITY ALERT] Production environment does not have database credentials configured (SQL_HOST/SQL_USER/SQL_DB_NAME or DATABASE_URL). Shared rate limiting store is absent and degradedModePolicy is fail_closed: protected endpoints will reject requests with HTTP 503.'
        : '[SECURITY ALERT] Production environment does not have database credentials configured (SQL_HOST/SQL_USER/SQL_DB_NAME or DATABASE_URL). Multi-instance shared rate limiting cannot be activated. Enforcing documented degraded rate-limiting policy (per-instance in-memory storage only; does NOT provide multi-instance protection).';
    console.error(warning);
    return {
      store: undefined,
      type: 'memory_fallback',
      degradedModePolicy,
      warning,
    };
  }

  return {
    store: undefined,
    type: 'memory_local',
    degradedModePolicy: env.RATE_LIMIT_DEGRADED_POLICY === 'fail_closed' ? 'fail_closed' : 'memory_fallback',
  };
}

/**
 * Bounded, self-pruning, churn-resistant rate limiter middleware.
 * - Supports both synchronous in-memory operation and shared multi-instance store (`sharedStore`).
 * - Protects active multi-hit security counters (`count > 1`) from being evicted by single-hit (`count === 1`)
 *   high-cardinality key churn.
 * - Supports independent secondary rules (e.g. separate per-IP, per-email, and combined IP+email limits).
 */
export function createBoundedRateLimiter(
  options: RateLimiterOptions
): BoundedRateLimiterMiddleware {
  const windowMs = Math.max(1000, options.windowMs);
  const maxRequests = Math.max(1, options.maxRequests);
  const maxKeys = Math.max(10, options.maxKeys ?? 5000);
  const scope = options.scope || 'default';
  const degradedModePolicy: 'memory_fallback' | 'fail_closed' =
    options.degradedModePolicy ||
    (process.env.NODE_ENV === 'production' ? 'fail_closed' : 'memory_fallback');
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

  /**
   * Ensures capacity for a new key without allowing high-cardinality single-hit key churn
   * to evict active multi-hit or rate-limited security counters (`count > 1`).
   * Returns true if capacity is available, or false if all slots are held by active multi-hit counters.
   */
  function ensureBoundedCapacity(now: number): boolean {
    if (store.size < maxKeys) return true;
    pruneExpired(now);
    if (store.size < maxKeys) return true;

    const toEvict = store.size - maxKeys + 1;
    let evicted = 0;

    // Pass 1: Evict only single-hit probe entries (count <= 1) in FIFO order.
    // Active security counters (count > 1) are strictly protected from key-churn eviction!
    for (const [candidateKey, entry] of store.entries()) {
      if (entry.count <= 1) {
        store.delete(candidateKey);
        evicted++;
        if (evicted >= toEvict) break;
      }
    }

    return store.size < maxKeys;
  }

  function consumeInMemory(
    key: string,
    ruleWindowMs: number,
    ruleMaxRequests: number,
    now: number
  ): RateLimitConsumeResult {
    const existing = store.get(key);
    if (!existing || now >= existing.resetAt) {
      if (existing) {
        store.delete(key);
      }
      const hasRoom = ensureBoundedCapacity(now);
      if (!hasRoom) {
        // All maxKeys slots are occupied by active multi-hit security counters; fail closed for new keys
        return {
          allowed: false,
          count: ruleMaxRequests + 1,
          resetAt: now + ruleWindowMs,
          maxRequests: ruleMaxRequests,
        };
      }
      const resetAt = now + ruleWindowMs;
      store.set(key, { count: 1, resetAt });
      return {
        allowed: true,
        count: 1,
        resetAt,
        maxRequests: ruleMaxRequests,
      };
    }

    if (existing.count >= ruleMaxRequests) {
      return {
        allowed: false,
        count: existing.count,
        resetAt: existing.resetAt,
        maxRequests: ruleMaxRequests,
      };
    }

    existing.count += 1;
    return {
      allowed: true,
      count: existing.count,
      resetAt: existing.resetAt,
      maxRequests: ruleMaxRequests,
    };
  }

  function buildRulesForRequest(req: Request): Array<{
    key: string;
    windowMs: number;
    maxRequests: number;
  }> {
    const customPart = options.keyGenerator
      ? options.keyGenerator(req)
      : `${normalizeClientIp(req, { trustProxy: options.trustProxy })}:${req.baseUrl || ''}${req.path || ''}`;
    const rules: Array<{ key: string; windowMs: number; maxRequests: number }> = [
      {
        key: `${scope}:${customPart.slice(0, 256)}`,
        windowMs,
        maxRequests,
      },
    ];

    if (Array.isArray(options.secondaryRules)) {
      for (let i = 0; i < options.secondaryRules.length; i++) {
        const sec = options.secondaryRules[i];
        const rawKey = sec.keyGenerator(req);
        if (typeof rawKey === 'string' && rawKey.trim().length > 0) {
          const ruleName = sec.name || sec.scopeSuffix || `sec${i}`;
          rules.push({
            key: `${scope}:${ruleName}:${rawKey.trim().slice(0, 256)}`,
            windowMs: Math.max(1000, sec.windowMs ?? windowMs),
            maxRequests: Math.max(1, sec.maxRequests),
          });
        }
      }
    }

    return rules;
  }

  function applyHeadersAndRespond(
    res: Response,
    next: NextFunction,
    results: RateLimitConsumeResult[],
    now: number
  ): void {
    const blocked = results.find((r) => !r.allowed);
    if (blocked) {
      const retryAfterSeconds = Math.max(1, Math.ceil((blocked.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      res.setHeader('X-RateLimit-Limit', String(blocked.maxRequests));
      res.setHeader('X-RateLimit-Remaining', '0');
      res.setHeader('X-RateLimit-Reset', String(Math.ceil(blocked.resetAt / 1000)));
      res.status(429).json({
        error: errorMessage,
        retryAfterSeconds,
      });
      return;
    }

    const primary = results[0];
    res.setHeader('X-RateLimit-Limit', String(primary.maxRequests));
    res.setHeader(
      'X-RateLimit-Remaining',
      String(Math.max(0, primary.maxRequests - primary.count))
    );
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(primary.resetAt / 1000)));
    next();
  }

  const activeSharedStore = options.sharedStore ?? options.store ?? null;

  const middleware = ((req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    if (now - lastSweepAt >= sweepIntervalMs) {
      pruneExpired(now);
    }

    const rules = buildRulesForRequest(req);

    // Synchronous path when no async sharedStore is attached
    if (!activeSharedStore) {
      if (degradedModePolicy === 'fail_closed') {
        res.setHeader('X-RateLimit-Protection', 'fail-closed-unavailable');
        res.status(503).json({
          error: 'Rate limiting service is temporarily unavailable. Please try again shortly.',
        });
        return;
      }

      // Explicit per-instance memory fallback: clearly observable and documented
      res.setHeader('X-RateLimit-Protection', 'per-instance-only');
      res.setHeader('X-RateLimit-Degraded-Mode', 'per-instance-memory-fallback');
      const results = rules.map((r) =>
        consumeInMemory(r.key, r.windowMs, r.maxRequests, now)
      );
      applyHeadersAndRespond(res, next, results, now);
      return;
    }

    // Asynchronous shared-store path (multi-instance PostgreSQL store)
    const sharedStore = activeSharedStore;
    return (async () => {
      try {
        const results: RateLimitConsumeResult[] = [];
        for (const r of rules) {
          const resItem = await sharedStore.consume({
            key: r.key,
            scope,
            windowMs: r.windowMs,
            maxRequests: r.maxRequests,
            maxKeys,
            nowMs: now,
          });
          results.push(resItem);
          if (!resItem.allowed) break;
        }
        res.setHeader('X-RateLimit-Protection', 'multi-instance-shared');
        applyHeadersAndRespond(res, next, results, now);
      } catch (storeErr: any) {
        console.error('Shared rate-limit store error:', {
          scope,
          message: storeErr?.message,
        });
        if (degradedModePolicy === 'fail_closed') {
          res.setHeader('X-RateLimit-Protection', 'fail-closed-unavailable');
          res.status(503).json({
            error: 'Rate limiting service is temporarily unavailable. Please try again shortly.',
          });
          return;
        }
        // Degraded mode: fall back to bounded churn-resistant in-memory store
        res.setHeader('X-RateLimit-Protection', 'per-instance-only');
        res.setHeader('X-RateLimit-Degraded-Mode', 'per-instance-memory-fallback');
        const fallbackResults = rules.map((r) =>
          consumeInMemory(r.key, r.windowMs, r.maxRequests, now)
        );
        applyHeadersAndRespond(res, next, fallbackResults, now);
      }
    })();
  }) as BoundedRateLimiterMiddleware;

  middleware.getStoreSize = () => store.size;
  middleware.pruneExpired = pruneExpired;
  middleware.clear = () => store.clear();

  return middleware;
}
