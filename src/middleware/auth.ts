import 'dotenv/config';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import * as dotenv from 'dotenv';
import { eq, or } from 'drizzle-orm';
import { adminAuth } from '../lib/firebase-admin.ts';
import { db } from '../db/index.ts';
import { users, deletedAccounts } from '../db/schema.ts';

// Ensure .env is loaded if the environment was pre-populated with a placeholder
if (!process.env.AUTH_SESSION_SECRET || process.env.AUTH_SESSION_SECRET.trim().length < 32) {
  dotenv.config({ override: true });
}

export const MIN_SESSION_SECRET_LENGTH = 32;
export const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
export const RECOVERY_TOKEN_TTL_MS = 1000 * 60 * 15; // 15 minutes

const FORBIDDEN_PLACEHOLDER_SECRETS = new Set([
  'medatlas_default_server_hmac_secret_2026_secure_key',
  'replace_with_at_least_32_byte_random_hex_secret',
  'my_auth_session_secret',
  'changeme',
  'secret',
  'default_secret',
]);

export interface AuthenticatedUser {
  uid: string;
  email: string;
  name?: string;
  tokenVersion?: number;
  authType?: 'local' | 'firebase';
  emailVerified?: boolean;
  iat?: number;
}

export interface AuthRequest extends Request {
  user?: AuthenticatedUser;
}

// Server-side revocation watermark map (supplements PostgreSQL tokenVersion & updatedAt)
const userRevocationTimestampsMs = new Map<string, number>();

export function recordUserSessionRevocation(uid: string, timestampMs = Date.now()): void {
  if (!uid) return;
  const prev = userRevocationTimestampsMs.get(uid) ?? 0;
  userRevocationTimestampsMs.set(uid, Math.max(prev, timestampMs));
}

export function getUserSessionRevocationTimestamp(uid: string): number | null {
  return userRevocationTimestampsMs.get(uid) ?? null;
}

export interface DecodedFirebaseTokenLike {
  uid: string;
  email?: string;
  name?: string;
  email_verified?: boolean;
  iat?: number;
  auth_time?: number;
  iatMs?: number;
}

type FirebaseVerifierFn = (
  token: string,
  checkRevoked: boolean
) => Promise<DecodedFirebaseTokenLike>;

let customFirebaseVerifierForTests: FirebaseVerifierFn | null = null;

export function setFirebaseTokenVerifierForTests(
  fn: FirebaseVerifierFn | null
): void {
  customFirebaseVerifierForTests = fn;
}

async function verifyFirebaseIdTokenWithRevocation(
  token: string
): Promise<DecodedFirebaseTokenLike> {
  if (customFirebaseVerifierForTests) {
    return customFirebaseVerifierForTests(token, true);
  }
  try {
    return (await adminAuth.verifyIdToken(token, true)) as DecodedFirebaseTokenLike;
  } catch (err: any) {
    const code = String(err?.code || err?.errorInfo?.code || '');
    // Re-throw explicit token/user security errors immediately
    if (
      code === 'auth/id-token-revoked' ||
      code === 'auth/user-disabled' ||
      code === 'auth/id-token-expired' ||
      code === 'auth/argument-error' ||
      code === 'auth/invalid-id-token'
    ) {
      throw err;
    }
    // If checkRevoked=true failed only because the runtime environment lacks IAM service-account
    // credentials for getUser metadata lookup, still verify the cryptographic signature and rely on
    // our PostgreSQL session revocation watermark & account status checks below.
    return (await adminAuth.verifyIdToken(token, false)) as DecodedFirebaseTokenLike;
  }
}

/**
 * Validates that a session signing secret is present, strong, and not a known placeholder.
 * Throws a descriptive error if the secret is missing or weak.
 */
export function validateSessionSecret(rawSecret: string | undefined): string {
  const secret = rawSecret?.trim() || '';
  if (!secret) {
    throw new Error(
      'CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SESSION_SECRET environment variable is required and must be at least 32 characters long.'
    );
  }
  if (FORBIDDEN_PLACEHOLDER_SECRETS.has(secret.toLowerCase())) {
    throw new Error(
      'CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SESSION_SECRET is set to a known placeholder or forbidden default secret.'
    );
  }
  if (secret.length < MIN_SESSION_SECRET_LENGTH) {
    throw new Error(
      `CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LENGTH} characters long (received ${secret.length}).`
    );
  }
  const uniqueChars = new Set(secret.split('')).size;
  if (uniqueChars < 10) {
    throw new Error(
      'CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SESSION_SECRET has insufficient entropy (requires at least 10 distinct characters).'
    );
  }
  return secret;
}

export function getSessionSecret(overrideSecret?: string): string {
  return validateSessionSecret(overrideSecret ?? process.env.AUTH_SESSION_SECRET);
}

/**
 * Invoked during server startup to fail fast if AUTH_SESSION_SECRET is missing or weak.
 */
export function validateAuthConfiguration(): void {
  getSessionSecret();
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  if (!password || !storedHash) return false;
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  if (!salt || !keyHex) return false;
  try {
    const derived = crypto.scryptSync(password, salt, 64);
    const keyBuf = Buffer.from(keyHex, 'hex');
    if (derived.length !== keyBuf.length || keyBuf.length === 0) return false;
    return crypto.timingSafeEqual(derived, keyBuf);
  } catch {
    return false;
  }
}

export function hashEmailForTombstone(email: string): string {
  return crypto
    .createHash('sha256')
    .update(email.toLowerCase().trim())
    .digest('hex');
}

export function hashRecoveryToken(rawToken: string): string {
  return crypto
    .createHash('sha256')
    .update(rawToken.trim())
    .digest('hex');
}

export function generateRecoveryToken(): {
  rawToken: string;
  tokenHash: string;
  expiresAt: Date;
} {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashRecoveryToken(rawToken);
  const expiresAt = new Date(Date.now() + RECOVERY_TOKEN_TTL_MS);
  return { rawToken, tokenHash, expiresAt };
}

export const SIX_DIGIT_CODE_TTL_MS = 1000 * 60 * 10; // 10 minutes

/**
 * Generates a cryptographically secure 6-digit numeric verification code (100000 - 999999).
 */
export function generateSixDigitCode(): string {
  const codeNum = crypto.randomInt(100000, 1000000);
  return codeNum.toString();
}

/**
 * Securely hashes a 6-digit recovery code using HMAC-SHA256 keyed with AUTH_SESSION_SECRET
 * and salted with the user's permanent unique identifier (userUid).
 * Because 6-digit numbers have 10^6 possible values, keyed HMAC + user salt completely
 * prevents offline precomputation and rainbow table attacks.
 */
export function hashSixDigitCode(code: string, userUid: string, secretOverride?: string): string {
  const secret = getSessionSecret(secretOverride);
  const normalizedCode = String(code || '').trim();
  const normalizedUid = String(userUid || '').trim();
  return crypto
    .createHmac('sha256', secret)
    .update(`${normalizedUid}:${normalizedCode}`)
    .digest('hex');
}

export interface ServerSessionTokenOptions {
  ttlMs?: number;
  secret?: string;
  nowMs?: number;
}

export function createServerSessionToken(
  payload: AuthenticatedUser,
  options?: ServerSessionTokenOptions
): string {
  const secret = getSessionSecret(options?.secret);
  const now = options?.nowMs ?? Date.now();
  const ttlMs = options?.ttlMs ?? SESSION_TTL_MS;
  const exp = now + ttlMs;
  const tokenVersion =
    typeof payload.tokenVersion === 'number' && Number.isInteger(payload.tokenVersion)
      ? payload.tokenVersion
      : 1;

  const claims = {
    iss: 'medatlas-local',
    uid: String(payload.uid),
    email: String(payload.email).toLowerCase().trim(),
    name: payload.name ? String(payload.name) : undefined,
    tokenVersion,
    emailVerified: Boolean(payload.emailVerified),
    iat: now,
    exp,
  };

  const data = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', secret)
    .update(`medatlas.v1.${data}`)
    .digest('base64url');

  return `medatlas.v1.${data}.${sig}`;
}

export function verifyServerSessionToken(
  token: string,
  options?: { secret?: string; nowMs?: number }
): AuthenticatedUser | null {
  if (!token || typeof token !== 'string') return null;
  if (!token.startsWith('medatlas.v1.')) return null;

  const parts = token.split('.');
  if (parts.length !== 4) return null;
  const [prefix, version, data, sig] = parts;
  if (prefix !== 'medatlas' || version !== 'v1' || !data || !sig) return null;

  let secret: string;
  try {
    secret = getSessionSecret(options?.secret);
  } catch {
    return null;
  }

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`medatlas.v1.${data}`)
    .digest('base64url');

  const sigBuf = Buffer.from(sig, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    const now = options?.nowMs ?? Date.now();
    if (!parsed || typeof parsed !== 'object') return null;
    if (parsed.iss !== 'medatlas-local') return null;
    if (!parsed.uid || typeof parsed.uid !== 'string') return null;
    if (!parsed.email || typeof parsed.email !== 'string') return null;
    if (typeof parsed.exp !== 'number' || !Number.isFinite(parsed.exp) || now > parsed.exp) {
      return null;
    }
    if (
      typeof parsed.tokenVersion !== 'number' ||
      !Number.isInteger(parsed.tokenVersion) ||
      parsed.tokenVersion < 1
    ) {
      return null;
    }

    return {
      uid: parsed.uid,
      email: parsed.email.toLowerCase().trim(),
      name: parsed.name ? String(parsed.name) : undefined,
      tokenVersion: parsed.tokenVersion,
      authType: 'local',
      emailVerified: Boolean(parsed.emailVerified),
      iat: typeof parsed.iat === 'number' ? parsed.iat : undefined,
    };
  } catch {
    return null;
  }
}

export interface UserSessionStateRecord {
  exists: boolean;
  isDeleted: boolean;
  isSuspendedOrInactive: boolean;
  accountStatus?: string;
  tokenVersion?: number;
  email?: string;
  displayName?: string;
  emailVerified?: boolean;
  revokedAtMs?: number | null;
}

export async function lookupUserSessionState(
  uid: string,
  email?: string
): Promise<UserSessionStateRecord> {
  const tombstoneConditions = [eq(deletedAccounts.uid, uid)];
  if (email) {
    tombstoneConditions.push(
      eq(deletedAccounts.emailHash, hashEmailForTombstone(email))
    );
  }

  const tombstones = await db
    .select()
    .from(deletedAccounts)
    .where(
      tombstoneConditions.length > 1
        ? or(...tombstoneConditions)
        : tombstoneConditions[0]
    );

  const userRows = await db.select().from(users).where(eq(users.uid, uid));
  const dbUser = userRows[0];

  const memRevokedAtMs = userRevocationTimestampsMs.get(uid) ?? null;

  if (!dbUser) {
    return {
      exists: false,
      isDeleted: tombstones.length > 0,
      isSuspendedOrInactive: false,
      revokedAtMs: memRevokedAtMs,
    };
  }

  const isDeleted =
    tombstones.length > 0 ||
    dbUser.deletedAt !== null ||
    dbUser.accountStatus === 'deleted';

  const isSuspendedOrInactive =
    !isDeleted && dbUser.accountStatus !== 'active';

  const dbRevokedAtMs =
    dbUser.tokenVersion > 1 && dbUser.updatedAt
      ? new Date(dbUser.updatedAt).getTime()
      : null;

  const revokedAtMs =
    dbRevokedAtMs !== null && memRevokedAtMs !== null
      ? Math.max(dbRevokedAtMs, memRevokedAtMs)
      : dbRevokedAtMs ?? memRevokedAtMs;

  return {
    exists: true,
    isDeleted,
    isSuspendedOrInactive,
    accountStatus: dbUser.accountStatus,
    tokenVersion: dbUser.tokenVersion,
    email: dbUser.email,
    displayName: dbUser.displayName,
    emailVerified: Boolean(dbUser.emailVerified),
    revokedAtMs,
  };
}

export const requireAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing authentication token' });
  }

  const token = authHeader.slice('Bearer '.length).trim();
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Empty authentication token' });
  }

  // Strictly separate local HMAC session tokens (prefix 'medatlas.') from Firebase ID tokens
  if (token.startsWith('medatlas.')) {
    const localSession = verifyServerSessionToken(token);
    if (!localSession) {
      return res.status(401).json({ error: 'Unauthorized: Invalid or expired session token' });
    }

    try {
      const state = await lookupUserSessionState(localSession.uid, localSession.email);
      if (!state.exists || state.isDeleted) {
        return res.status(401).json({
          error: 'Unauthorized: Account no longer exists or has been deleted.',
        });
      }
      if (state.isSuspendedOrInactive) {
        return res.status(403).json({
          error: 'Forbidden: This account is suspended or inactive.',
        });
      }
      if (state.tokenVersion !== localSession.tokenVersion) {
        return res.status(401).json({
          error: 'Unauthorized: Session has been revoked. Please sign in again.',
        });
      }
      if (
        state.revokedAtMs !== null &&
        state.revokedAtMs !== undefined &&
        localSession.iat !== undefined &&
        localSession.iat <= state.revokedAtMs
      ) {
        return res.status(401).json({
          error: 'Unauthorized: Session has been revoked. Please sign in again.',
        });
      }

      req.user = {
        uid: localSession.uid,
        email: state.email || localSession.email,
        name: state.displayName || localSession.name,
        tokenVersion: state.tokenVersion,
        authType: 'local',
        emailVerified: Boolean(state.emailVerified),
      };
      return next();
    } catch (error) {
      console.error('Error verifying local session account state:', error);
      return res.status(500).json({ error: 'Authentication verification failed.' });
    }
  }

  // Otherwise verify strictly as a Firebase Auth ID token
  try {
    const decodedToken = await verifyFirebaseIdTokenWithRevocation(token);
    if (!decodedToken || !decodedToken.uid) {
      return res.status(401).json({ error: 'Unauthorized: Invalid authentication token' });
    }
    if (!decodedToken.email) {
      return res.status(401).json({
        error: 'Unauthorized: Verified email address is required on authentication token.',
      });
    }
    if (decodedToken.email_verified !== true) {
      return res.status(403).json({
        error: 'Forbidden: Please verify your email address before accessing your account.',
      });
    }

    const state = await lookupUserSessionState(decodedToken.uid, decodedToken.email);
    if (state.isDeleted) {
      return res.status(401).json({
        error: 'Unauthorized: This account has been deleted.',
      });
    }
    if (state.isSuspendedOrInactive) {
      return res.status(403).json({
        error: 'Forbidden: This account is suspended or inactive.',
      });
    }

    // Compare token issuance / authentication timestamp against server-side revocation watermark
    const tokenIssuedSec =
      typeof decodedToken.iat === 'number'
        ? decodedToken.iat
        : typeof decodedToken.auth_time === 'number'
        ? decodedToken.auth_time
        : null;
    const tokenIssuedMs =
      typeof decodedToken.iatMs === 'number'
        ? decodedToken.iatMs
        : tokenIssuedSec !== null
        ? tokenIssuedSec * 1000
        : null;

    if (
      state.revokedAtMs !== null &&
      state.revokedAtMs !== undefined &&
      (tokenIssuedMs === null || tokenIssuedMs <= state.revokedAtMs)
    ) {
      return res.status(401).json({
        error: 'Unauthorized: Session has been revoked. Please sign in again.',
      });
    }

    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email.toLowerCase().trim(),
      name: decodedToken.name,
      tokenVersion: state.tokenVersion ?? 1,
      authType: 'firebase',
      emailVerified: true,
    };
    return next();
  } catch (err: any) {
    const code = String(err?.code || err?.errorInfo?.code || '');
    if (code === 'auth/id-token-revoked') {
      return res.status(401).json({
        error: 'Unauthorized: Session has been revoked. Please sign in again.',
      });
    }
    if (code === 'auth/user-disabled') {
      return res.status(403).json({
        error: 'Forbidden: This account has been disabled.',
      });
    }
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
};
