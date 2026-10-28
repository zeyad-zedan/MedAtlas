import 'dotenv/config';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import * as dotenv from 'dotenv';
import { eq, or } from 'drizzle-orm';
import { adminAuth } from '../lib/firebase-admin.ts';
import { db } from '../db/index.ts';
import { users, deletedAccounts } from '../db/schema.ts';
import firebaseConfig from '../../firebase-applet-config.json' with { type: 'json' };

// Ensure .env is loaded if the environment was pre-populated with a placeholder
if (!process.env.AUTH_SESSION_SECRET || process.env.AUTH_SESSION_SECRET.trim().length < 32) {
  dotenv.config({ override: true });
}

export const MIN_SESSION_SECRET_LENGTH = 32;
export const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
export const RECOVERY_TOKEN_TTL_MS = 1000 * 60 * 15; // 15 minutes

export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;
export const MAX_PASSWORD_BYTES = 512;

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
  firebaseUid?: string | null;
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

// Server-side in-memory revocation watermark map (supplements PostgreSQL sessionsRevokedAt & tokenVersion)
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
  revocationFallbackUsed?: boolean;
}

type FirebaseVerifierFn = (
  token: string,
  checkRevoked: boolean
) => Promise<DecodedFirebaseTokenLike>;

export type FirebaseLookupRestResultForTests = {
  status: 'ok' | 'error';
  disabled?: boolean;
  validSinceSec?: number;
  errorCode?: string;
};

export type FirebaseLookupRestHandlerForTests = (
  rawIdToken: string,
  decoded: DecodedFirebaseTokenLike
) => Promise<FirebaseLookupRestResultForTests>;

let customFirebaseVerifierForTests: FirebaseVerifierFn | null = null;
let customFirebaseLookupRestForTests: FirebaseLookupRestHandlerForTests | null = null;

export function setFirebaseTokenVerifierForTests(
  fn: FirebaseVerifierFn | null
): void {
  if (process.env.NODE_ENV !== 'test' && fn !== null) {
    throw new Error(
      'Security violation: setFirebaseTokenVerifierForTests is forbidden outside test environment.'
    );
  }
  customFirebaseVerifierForTests = fn;
}

export function setFirebaseLookupRestHandlerForTests(
  fn: FirebaseLookupRestHandlerForTests | null
): void {
  if (process.env.NODE_ENV !== 'test' && fn !== null) {
    throw new Error(
      'Security violation: setFirebaseLookupRestHandlerForTests is forbidden outside test environment.'
    );
  }
  customFirebaseLookupRestForTests = fn;
}

/**
 * Verifies a Firebase ID token via Identity Toolkit accounts:lookup using the project's API key
 * when the runtime environment lacks IAM service-account credentials for Admin SDK getUser().
 * Fails closed if the user is disabled, deleted, or the token is revoked/expired.
 */
async function verifyTokenLiveStatusViaIdentityToolkit(
  rawIdToken: string,
  decoded: DecodedFirebaseTokenLike
): Promise<void> {
  if (process.env.NODE_ENV === 'test' && customFirebaseLookupRestForTests) {
    const mockRes = await customFirebaseLookupRestForTests(rawIdToken, decoded);
    if (mockRes.status !== 'ok') {
      const err: any = new Error(mockRes.errorCode || 'Lookup failed');
      err.code = 'auth/internal-error';
      err.isTransientProviderError = true;
      throw err;
    }
    if (mockRes.disabled === true) {
      const err: any = new Error('This account has been disabled.');
      err.code = 'auth/user-disabled';
      throw err;
    }
    if (typeof mockRes.validSinceSec === 'number') {
      const tokenIatSec =
        typeof decoded.iat === 'number'
          ? decoded.iat
          : typeof decoded.auth_time === 'number'
          ? decoded.auth_time
          : 0;
      if (tokenIatSec < mockRes.validSinceSec) {
        const err: any = new Error('Firebase ID token has been revoked.');
        err.code = 'auth/id-token-revoked';
        throw err;
      }
    }
    return;
  }

  const apiKey = firebaseConfig?.apiKey?.trim();
  if (!apiKey) {
    const err: any = new Error('Firebase API key unavailable for live revocation check.');
    err.code = 'auth/internal-error';
    err.isTransientProviderError = true;
    throw err;
  }

  let res: globalThis.Response;
  try {
    res = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: rawIdToken }),
      }
    );
  } catch (networkErr: any) {
    const err: any = new Error(
      `Failed to contact Identity Toolkit for token revocation verification: ${networkErr?.message || 'network error'}`
    );
    err.code = 'auth/network-request-failed';
    err.isTransientProviderError = true;
    throw err;
  }

  if (!res.ok) {
    const body: any = await res.json().catch(() => null);
    const msg = String(body?.error?.message || '');
    if (msg === 'USER_DISABLED') {
      const err: any = new Error('This account has been disabled.');
      err.code = 'auth/user-disabled';
      throw err;
    }
    if (msg === 'TOKEN_EXPIRED' || msg === 'INVALID_ID_TOKEN' || msg === 'USER_NOT_FOUND') {
      const err: any = new Error('Firebase ID token has been revoked or invalidated.');
      err.code = 'auth/id-token-revoked';
      throw err;
    }
    const err: any = new Error(`Identity Toolkit lookup failed (${res.status}): ${msg}`);
    err.code = 'auth/internal-error';
    err.isTransientProviderError = true;
    throw err;
  }

  const data: any = await res.json().catch(() => null);
  const account = Array.isArray(data?.users) ? data.users[0] : null;
  if (!account || account.localId !== decoded.uid) {
    const err: any = new Error('Firebase account lookup did not match token subject.');
    err.code = 'auth/invalid-id-token';
    throw err;
  }
  if (account.disabled === true) {
    const err: any = new Error('This account has been disabled.');
    err.code = 'auth/user-disabled';
    throw err;
  }
  if (account.validSince) {
    const validSinceSec = Number.parseInt(String(account.validSince), 10);
    const tokenIatSec =
      typeof decoded.iat === 'number'
        ? decoded.iat
        : typeof decoded.auth_time === 'number'
        ? decoded.auth_time
        : 0;
    if (Number.isFinite(validSinceSec) && tokenIatSec < validSinceSec) {
      const err: any = new Error('Firebase ID token has been revoked.');
      err.code = 'auth/id-token-revoked';
      throw err;
    }
  }
}

/**
 * Verifies a Firebase ID token with revocation checking (`checkRevoked = true`).
 * Security policy (Fails Closed):
 * - Explicitly rejected tokens (`auth/id-token-revoked`, `auth/user-disabled`, `auth/id-token-expired`,
 *   `auth/argument-error`, `auth/invalid-id-token`, `auth/user-not-found`) are rejected immediately.
 * - Network timeouts, generic Firebase errors, permission denials, or unknown provider errors
 *   NEVER fall back to `verifyIdToken(token, false)` and NEVER accept the token.
 * - Narrowly recognized local/container ADC credential absence (`app/invalid-credential`) is permitted
 *   to verify the JWT signature via `verifyIdToken(token, false)` ONLY when backed by authoritative
 *   database session-revocation state (`sessionsRevokedAt`) or live Identity Toolkit `accounts:lookup`.
 */
export async function verifyFirebaseIdTokenWithRevocation(
  token: string
): Promise<DecodedFirebaseTokenLike> {
  const verifier: FirebaseVerifierFn =
    process.env.NODE_ENV === 'test' && customFirebaseVerifierForTests
      ? customFirebaseVerifierForTests
      : async (t, checkRevoked) =>
          (await adminAuth.verifyIdToken(t, checkRevoked)) as DecodedFirebaseTokenLike;

  try {
    return await verifier(token, true);
  } catch (err: any) {
    const code = String(err?.code || err?.errorInfo?.code || '');
    const msg = String(err?.message || '');

    // 1. Definitive token or account rejection errors -> rethrow immediately
    if (
      code === 'auth/id-token-revoked' ||
      code === 'auth/user-disabled' ||
      code === 'auth/id-token-expired' ||
      code === 'auth/argument-error' ||
      code === 'auth/invalid-id-token' ||
      code === 'auth/user-not-found'
    ) {
      throw err;
    }

    // 2. Narrowly recognized local/container ADC credential configuration absence for Admin SDK getUser()
    const isNarrowAdcConfigAbsence =
      code === 'app/invalid-credential' &&
      !msg.toLowerCase().includes('timeout') &&
      !msg.toLowerCase().includes('econnreset') &&
      !msg.toLowerCase().includes('enotfound') &&
      !msg.toLowerCase().includes('network');

    if (isNarrowAdcConfigAbsence) {
      const decoded = await verifier(token, false);
      return {
        ...decoded,
        revocationFallbackUsed: true,
      };
    }

    // 3. Any other error (network timeout, generic Firebase error, IAM permission error, unknown error):
    // Fail closed! Mark as transient provider failure if not a malformed token error so requireAuth
    // returns 503 Service Unavailable without ever accepting a token whose revocation status is unknown.
    err.isTransientProviderError = true;
    throw err;
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

/**
 * Validates password type, character bounds, and UTF-8 byte bounds BEFORE any expensive scrypt work.
 * Never truncates passwords. Supports Unicode passphrases up to 128 characters / 512 bytes.
 */
export function validatePasswordBounds(
  password: unknown,
  options?: { fieldName?: string; requireMinLength?: boolean }
): { valid: boolean; error?: string; value?: string } {
  const fieldName = options?.fieldName || 'Password';
  const requireMinLength = options?.requireMinLength ?? true;

  if (typeof password !== 'string') {
    return { valid: false, error: `${fieldName} must be a valid string.` };
  }
  if (password.length === 0) {
    return { valid: false, error: `${fieldName} is required.` };
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return {
      valid: false,
      error: `${fieldName} must not exceed ${MAX_PASSWORD_LENGTH} characters.`,
    };
  }
  const byteLength = Buffer.byteLength(password, 'utf8');
  if (byteLength > MAX_PASSWORD_BYTES) {
    return {
      valid: false,
      error: `${fieldName} exceeds maximum allowed length (${MAX_PASSWORD_BYTES} bytes).`,
    };
  }
  if (requireMinLength && password.length < MIN_PASSWORD_LENGTH) {
    return {
      valid: false,
      error: `${fieldName} must be at least ${MIN_PASSWORD_LENGTH} characters long.`,
    };
  }
  return { valid: true, value: password };
}

export function hashPassword(password: string): string {
  const check = validatePasswordBounds(password, { requireMinLength: true });
  if (!check.valid) {
    throw new Error(check.error);
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export async function hashPasswordAsync(password: string): Promise<string> {
  const check = validatePasswordBounds(password, { requireMinLength: true });
  if (!check.valid) {
    throw new Error(check.error);
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
  return `${salt}:${derived.toString('hex')}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  if (typeof password !== 'string' || typeof storedHash !== 'string') return false;
  if (
    password.length === 0 ||
    password.length > MAX_PASSWORD_LENGTH ||
    Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES ||
    !storedHash
  ) {
    return false;
  }
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

export async function verifyPasswordAsync(
  password: string,
  storedHash: string
): Promise<boolean> {
  if (typeof password !== 'string' || typeof storedHash !== 'string') return false;
  if (
    password.length === 0 ||
    password.length > MAX_PASSWORD_LENGTH ||
    Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES ||
    !storedHash
  ) {
    return false;
  }
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  if (!salt || !keyHex) return false;
  try {
    const derived = await new Promise<Buffer>((resolve, reject) => {
      crypto.scrypt(password, salt, 64, (err, key) => {
        if (err) reject(err);
        else resolve(key);
      });
    });
    const keyBuf = Buffer.from(keyHex, 'hex');
    if (derived.length !== keyBuf.length || keyBuf.length === 0) return false;
    return crypto.timingSafeEqual(derived, keyBuf);
  } catch {
    return false;
  }
}

// Pre-computed dummy scrypt hash to equalize login timing when an email does not exist
export const DUMMY_SCRYPT_HASH = hashPassword('DummyConstantTimeMitigationPass123!');

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
  hasIdentityConflict: boolean;
  canonicalUid?: string;
  firebaseUid?: string | null;
  accountStatus?: string;
  tokenVersion?: number;
  email?: string;
  displayName?: string;
  emailVerified?: boolean;
  revokedAtMs?: number | null;
}

/**
 * Looks up the authoritative session state for a user in PostgreSQL.
 * - Enforces permanent UID and firebaseUid tombstones in `deleted_accounts`.
 * - If an email was deleted and later re-registered under a brand-new UID, preserves deletion
 *   protection for the old UID/firebaseUid and any token issued before the tombstone timestamp,
 *   while allowing the newly registered account's own UID and tokens to function.
 * - Uses the dedicated `users.sessionsRevokedAt` timestamp (never `users.updatedAt`) so ordinary
 *   profile updates do not invalidate sessions.
 */
export async function lookupUserSessionState(
  uid: string,
  email?: string,
  options?: { authType?: 'local' | 'firebase'; tokenIssuedMs?: number | null }
): Promise<UserSessionStateRecord> {
  const normalizedEmail = email ? email.toLowerCase().trim() : undefined;

  // 1. Check permanent tombstones by uid, firebaseUid, and emailHash
  const tombstoneConditions = [
    eq(deletedAccounts.uid, uid),
    eq(deletedAccounts.firebaseUid, uid),
  ];
  if (normalizedEmail) {
    tombstoneConditions.push(
      eq(deletedAccounts.emailHash, hashEmailForTombstone(normalizedEmail))
    );
  }

  const tombstones = await db
    .select()
    .from(deletedAccounts)
    .where(or(...tombstoneConditions));

  // Any tombstone matching the exact UID or firebaseUid is permanently deleted forever
  const directUidTombstone = tombstones.some(
    (t) => t.uid === uid || (t.firebaseUid !== null && t.firebaseUid === uid)
  );

  // 2. Look up user by uid or firebaseUid (and check email for identity conflict)
  const userLookupConditions = [eq(users.uid, uid), eq(users.firebaseUid, uid)];
  if (normalizedEmail) {
    userLookupConditions.push(eq(users.email, normalizedEmail));
  }

  const matchedUsers = await db
    .select()
    .from(users)
    .where(or(...userLookupConditions));

  const dbUserByIdentity =
    matchedUsers.find((u) => u.uid === uid || u.firebaseUid === uid) ?? null;
  const dbUserByEmail = normalizedEmail
    ? matchedUsers.find((u) => u.email.toLowerCase().trim() === normalizedEmail) ?? null
    : null;

  // Detect identity conflict: an active PostgreSQL account owns this email,
  // but the presenting token's UID matches neither its primary uid nor its mapped firebaseUid!
  if (
    !dbUserByIdentity &&
    dbUserByEmail &&
    dbUserByEmail.deletedAt === null &&
    dbUserByEmail.accountStatus !== 'deleted'
  ) {
    return {
      exists: false,
      isDeleted: directUidTombstone,
      isSuspendedOrInactive: false,
      hasIdentityConflict: true,
      revokedAtMs: userRevocationTimestampsMs.get(uid) ?? null,
    };
  }

  const dbUser = dbUserByIdentity;
  const memRevokedAtMs =
    userRevocationTimestampsMs.get(uid) ??
    (dbUser ? userRevocationTimestampsMs.get(dbUser.uid) ?? null : null);

  if (!dbUser) {
    return {
      exists: false,
      isDeleted: directUidTombstone || tombstones.length > 0,
      isSuspendedOrInactive: false,
      hasIdentityConflict: false,
      revokedAtMs: memRevokedAtMs,
    };
  }

  // Also check if an email tombstone is newer than or equal to the current user's creation time
  // or newer than the presented token's issuance timestamp
  const latestEmailTombstoneMs = tombstones.reduce((maxMs, t) => {
    const tMs = t.deletedAt ? new Date(t.deletedAt).getTime() : 0;
    return Math.max(maxMs, tMs);
  }, 0);

  const userCreatedAtMs = dbUser.createdAt ? new Date(dbUser.createdAt).getTime() : 0;
  const isTombstonedByTimestamp =
    latestEmailTombstoneMs > 0 &&
    (userCreatedAtMs < latestEmailTombstoneMs ||
      (typeof options?.tokenIssuedMs === 'number' &&
        options.tokenIssuedMs <= latestEmailTombstoneMs));

  const isDeleted =
    directUidTombstone ||
    isTombstonedByTimestamp ||
    dbUser.deletedAt !== null ||
    dbUser.accountStatus === 'deleted';

  const isSuspendedOrInactive = !isDeleted && dbUser.accountStatus !== 'active';

  // If the authenticated user has a different email in the token than the email bound to their DB row, flag conflict
  const hasIdentityConflict = Boolean(
    normalizedEmail && dbUser.email.toLowerCase().trim() !== normalizedEmail
  );

  // Dedicated session revocation timestamp: ONLY derived from users.sessionsRevokedAt (never updatedAt)
  const dbRevokedAtMs = dbUser.sessionsRevokedAt
    ? new Date(dbUser.sessionsRevokedAt).getTime()
    : null;

  const revokedAtMs =
    dbRevokedAtMs !== null && memRevokedAtMs !== null
      ? Math.max(dbRevokedAtMs, memRevokedAtMs)
      : dbRevokedAtMs ?? memRevokedAtMs;

  return {
    exists: true,
    isDeleted,
    isSuspendedOrInactive,
    hasIdentityConflict,
    canonicalUid: dbUser.uid,
    firebaseUid: dbUser.firebaseUid,
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
      const state = await lookupUserSessionState(localSession.uid, localSession.email, {
        authType: 'local',
        tokenIssuedMs: localSession.iat ?? null,
      });
      if (!state.exists || state.isDeleted) {
        return res.status(401).json({
          error: 'Unauthorized: Account no longer exists or has been deleted.',
        });
      }
      if (state.hasIdentityConflict) {
        return res.status(409).json({
          error: 'Conflict: Session identity does not match the bound account.',
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
        uid: state.canonicalUid || localSession.uid,
        firebaseUid: state.firebaseUid,
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

    const state = await lookupUserSessionState(decodedToken.uid, decodedToken.email, {
      authType: 'firebase',
      tokenIssuedMs,
    });

    if (state.isDeleted) {
      return res.status(401).json({
        error: 'Unauthorized: This account has been deleted.',
      });
    }
    if (state.hasIdentityConflict) {
      return res.status(409).json({
        error:
          'An account with this email address already exists under a different sign-in method. Please sign in using your original credentials.',
      });
    }
    if (state.isSuspendedOrInactive) {
      return res.status(403).json({
        error: 'Forbidden: This account is suspended or inactive.',
      });
    }

    // If Admin SDK checkRevoked fell back due to narrow ADC config absence AND the user is not yet
    // tracked in PostgreSQL (or a test lookup handler is registered), verify live revocation via Identity Toolkit
    if (
      decodedToken.revocationFallbackUsed &&
      ((process.env.NODE_ENV === 'test' && customFirebaseLookupRestForTests !== null) ||
        (!state.exists && !(process.env.NODE_ENV === 'test' && customFirebaseVerifierForTests)))
    ) {
      await verifyTokenLiveStatusViaIdentityToolkit(token, decodedToken);
    }

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
      uid: state.canonicalUid || decodedToken.uid,
      firebaseUid: decodedToken.uid,
      email: decodedToken.email.toLowerCase().trim(),
      name: state.displayName || decodedToken.name,
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
    if (err?.isTransientProviderError) {
      return res.status(503).json({
        error:
          'Authentication verification service is temporarily unavailable. Please try again shortly.',
      });
    }
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
};
