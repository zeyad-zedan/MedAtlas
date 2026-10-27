import { eq, and, desc, asc, inArray, isNull, sql } from 'drizzle-orm';
import { db } from './index.ts';
import {
  users,
  subjects,
  lectures,
  questionBanks,
  questions,
  examSessions,
  questionAttempts,
  bookmarks,
  importBatches,
  adminAuditLogs,
  passwordResetTokens,
  deletedAccounts,
} from './schema.ts';
import {
  computeContentHash,
  createOptionPermutation,
  formatQuestionForClient,
  resolveCanonicalOption,
  scoreExamSession,
  selectPracticeQuestions,
  computeTopicPerformance,
  parseAndValidateCsvQuestions,
  OPTION_KEYS,
} from '../lib/mcq-engine.ts';
import type {
  OptionKey,
  OptionPermutation,
  DifficultyLevel,
  ContentStatus,
  CanonicalQuestion,
} from '../lib/mcq-engine.ts';
import {
  hashPassword,
  verifyPassword,
  generateRecoveryToken,
  hashRecoveryToken,
  hashEmailForTombstone,
} from '../middleware/auth.ts';
import { adminAuth } from '../lib/firebase-admin.ts';

export const OWNER_ADMIN_EMAIL = 'zeyadzedan098@gmail.com';
export const EXAM_SUBMISSION_GRACE_SECONDS = 15;
export const GENERIC_PASSWORD_RECOVERY_MESSAGE =
  'If an account exists for that email address, password recovery instructions have been initiated.';

/**
 * Error class representing messages that are safe to return to the client
 * with an explicit HTTP status code. Unexpected internal errors do not use this class
 * and are masked with a generic message at the HTTP boundary.
 */
export class ClientSafeError extends Error {
  public readonly statusCode: number;

  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'ClientSafeError';
    this.statusCode = statusCode;
  }
}

export function isOwnerAdminEmail(email: string): boolean {
  return email.toLowerCase().trim() === OWNER_ADMIN_EMAIL;
}

export async function ensureSeededDatabase() {
  // Automatic sample seeding is disabled so deleted subjects, lectures, and quizzes remain permanently deleted.
  return;
}

export function sanitizeUserForClient<T extends { passwordHash?: string | null }>(
  user: T
): Omit<T, 'passwordHash'> & { hasPassword: boolean } {
  const { passwordHash, ...safeUser } = user;
  return {
    ...safeUser,
    hasPassword: Boolean(passwordHash && passwordHash.length > 0),
  };
}

/**
 * Looks up an already-existing active user by UID without creating or resurrecting accounts.
 */
export async function getAuthenticatedUserByUid(uid: string) {
  const tombstones = await db
    .select()
    .from(deletedAccounts)
    .where(eq(deletedAccounts.uid, uid));

  if (tombstones.length > 0) {
    throw new ClientSafeError('Unauthorized: This account has been deleted.', 401);
  }

  const rows = await db.select().from(users).where(eq(users.uid, uid));
  const user = rows[0];
  if (!user || user.accountStatus !== 'active' || user.deletedAt !== null) {
    return null;
  }

  if (isOwnerAdminEmail(user.email) && user.role !== 'admin') {
    const [promotedOwner] = await db
      .update(users)
      .set({ role: 'admin', updatedAt: new Date() })
      .where(eq(users.uid, uid))
      .returning();
    return promotedOwner;
  }

  return user;
}

/**
 * Synchronizes or provisions a user authenticated via a verified Firebase ID token,
 * or returns the existing database profile for a local session user.
 * Never resurrects deleted accounts and never overwrites an existing user's UID.
 */
export async function getOrCreateUser(
  uid: string,
  email: string,
  displayName?: string,
  options?: {
    authType?: 'local' | 'firebase';
    emailVerified?: boolean;
    allowCreate?: boolean;
  }
) {
  try {
    await ensureSeededDatabase();
    const normalizedEmail = email.toLowerCase().trim();
    const isOwner = isOwnerAdminEmail(normalizedEmail);
    const defaultName =
      displayName?.trim() || normalizedEmail.split('@')[0] || 'Medical Student';

    // 1. Check tombstone table first so deleted UIDs can never be resurrected
    const tombstoneRows = await db
      .select()
      .from(deletedAccounts)
      .where(eq(deletedAccounts.uid, uid));

    if (tombstoneRows.length > 0) {
      throw new ClientSafeError('Unauthorized: This account has been deleted.', 401);
    }

    // 2. Check existing user by UID
    const existingByUid = await db
      .select()
      .from(users)
      .where(eq(users.uid, uid));

    if (existingByUid.length > 0) {
      const user = existingByUid[0];
      if (user.accountStatus !== 'active' || user.deletedAt !== null) {
        throw new ClientSafeError('Unauthorized: This account has been deactivated or deleted.', 401);
      }
      if (isOwner && user.role !== 'admin') {
        const [promotedOwner] = await db
          .update(users)
          .set({ role: 'admin', updatedAt: new Date() })
          .where(eq(users.uid, uid))
          .returning();
        return promotedOwner;
      }
      return user;
    }

    // Local session tokens must correspond to an already-registered database row;
    // never auto-create a user from a local token if the row was deleted.
    if (options?.authType === 'local' || options?.allowCreate === false || uid.startsWith('usr_')) {
      throw new ClientSafeError('Unauthorized: Account no longer exists.', 401);
    }

    // 3. For Firebase-authenticated users, require verified email before provisioning
    if (options?.emailVerified === false) {
      throw new ClientSafeError(
        'Forbidden: A verified email address is required to create or access an account.',
        403
      );
    }

    // 4. Check if another account already owns this email address.
    // Never overwrite an existing account's UID!
    const existingByEmail = await db
      .select()
      .from(users)
      .where(eq(users.email, normalizedEmail));

    if (existingByEmail.length > 0) {
      const existingUser = existingByEmail[0];
      if (existingUser.uid !== uid) {
        throw new ClientSafeError(
          'An account with this email address already exists under a different sign-in method. Please sign in using your original credentials.',
          409
        );
      }
      return existingUser;
    }

    const initialRole = isOwner ? 'admin' : 'student';
    const [created] = await db
      .insert(users)
      .values({
        uid,
        email: normalizedEmail,
        displayName: defaultName,
        authProvider: 'firebase',
        role: initialRole,
        subscriptionTier: 'free_trial',
        subscriptionStatus: 'active',
        accountStatus: 'active',
        tokenVersion: 1,
        emailVerified: true,
      })
      .returning();

    return created;
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    if (error?.code === '23505') {
      throw new ClientSafeError(
        'An account with this email address already exists.',
        409
      );
    }
    console.error('Database error in getOrCreateUser:', error);
    throw new Error('Failed to synchronize user profile.', { cause: error });
  }
}

/**
 * Registers a brand-new local email/password user.
 * Security guarantee: NEVER attaches a password to an existing user account (whether local or provider-based).
 */
export async function registerEmailPasswordUser(
  email: string,
  password: string,
  displayName: string
) {
  try {
    await ensureSeededDatabase();
    const normalizedEmail = email.toLowerCase().trim();
    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      throw new ClientSafeError('Please provide a valid email address.', 400);
    }
    if (!password || password.length < 8) {
      throw new ClientSafeError('Password must be at least 8 characters long.', 400);
    }
    if (!displayName || displayName.trim().length < 2) {
      throw new ClientSafeError(
        'Please enter your full name or display name (at least 2 characters).',
        400
      );
    }

    const isOwner = isOwnerAdminEmail(normalizedEmail);
    const passwordHash = hashPassword(password);

    const existing = await db
      .select()
      .from(users)
      .where(eq(users.email, normalizedEmail));

    if (existing.length > 0) {
      // Uniform conflict error: never attach a password to an existing account during unauthenticated registration
      throw new ClientSafeError(
        'An account with this email address already exists. Please sign in instead.',
        409
      );
    }

    const uid = `usr_${computeContentHash(`${normalizedEmail}_${Date.now()}_${Math.random()}`)}`;
    const initialRole = isOwner ? 'admin' : 'student';

    const created = await db.transaction(async (tx) => {
      // Clear any historical email-hash tombstone if this email is re-registering fresh with a brand-new UID
      await tx
        .delete(deletedAccounts)
        .where(eq(deletedAccounts.emailHash, hashEmailForTombstone(normalizedEmail)));

      const [inserted] = await tx
        .insert(users)
        .values({
          uid,
          email: normalizedEmail,
          displayName: displayName.trim(),
          passwordHash,
          authProvider: 'local',
          role: initialRole,
          subscriptionTier: 'free_trial',
          subscriptionStatus: 'active',
          accountStatus: 'active',
          tokenVersion: 1,
          emailVerified: true,
        })
        .returning();

      return inserted;
    });

    return created;
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    if (error?.code === '23505') {
      throw new ClientSafeError(
        'An account with this email address already exists. Please sign in instead.',
        409
      );
    }
    console.error('Error registering user:', error);
    throw new Error('Failed to register account. Please try again.', { cause: error });
  }
}

export async function findUserByEmail(email: string) {
  try {
    await ensureSeededDatabase();
    const normalizedEmail = email.toLowerCase().trim();
    const rows = await db
      .select()
      .from(users)
      .where(eq(users.email, normalizedEmail));
    const user = rows[0] || null;
    if (!user || user.accountStatus !== 'active' || user.deletedAt !== null) {
      return null;
    }

    if (isOwnerAdminEmail(normalizedEmail) && user.role !== 'admin') {
      const [promotedOwner] = await db
        .update(users)
        .set({ role: 'admin', updatedAt: new Date() })
        .where(eq(users.uid, user.uid))
        .returning();
      return promotedOwner;
    }
    return user;
  } catch (error) {
    console.error('Error finding user by email:', error);
    throw new Error('Database lookup failed.', { cause: error });
  }
}

/**
 * Initiates a password recovery flow using a single-use, short-lived cryptographic token.
 * Stores only the SHA-256 hash of the token in the database, invalidates prior unconsumed tokens
 * for the account, and returns a uniform enumeration-safe message.
 */
export async function requestPasswordRecoveryToken(
  email: string,
  options?: { returnTokenForTesting?: boolean }
): Promise<{
  accepted: true;
  message: string;
  expiresInMinutes: number;
  _testRecoveryToken?: string;
}> {
  try {
    const normalizedEmail = String(email || '').toLowerCase().trim();
    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      throw new ClientSafeError('Please provide a valid email address.', 400);
    }

    const user = await findUserByEmail(normalizedEmail);
    if (!user) {
      return {
        accepted: true,
        message: GENERIC_PASSWORD_RECOVERY_MESSAGE,
        expiresInMinutes: 15,
      };
    }

    const { rawToken, tokenHash, expiresAt } = generateRecoveryToken();
    const now = new Date();

    await db.transaction(async (tx) => {
      // Invalidate any previous unconsumed recovery tokens for this user
      await tx
        .update(passwordResetTokens)
        .set({ consumedAt: now })
        .where(
          and(
            eq(passwordResetTokens.userUid, user.uid),
            isNull(passwordResetTokens.consumedAt)
          )
        );

      await tx.insert(passwordResetTokens).values({
        userUid: user.uid,
        tokenHash,
        expiresAt,
      });
    });

    // Optional external email webhook delivery when configured in deployment environment
    const webhookUrl = process.env.PASSWORD_RESET_WEBHOOK_URL?.trim();
    if (webhookUrl) {
      try {
        await fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: user.email,
            displayName: user.displayName,
            expiresAt: expiresAt.toISOString(),
            resetToken: rawToken,
          }),
        });
      } catch (deliveryErr) {
        console.error('Password recovery webhook delivery failed:', deliveryErr);
      }
    }

    const response: {
      accepted: true;
      message: string;
      expiresInMinutes: number;
      _testRecoveryToken?: string;
    } = {
      accepted: true,
      message: GENERIC_PASSWORD_RECOVERY_MESSAGE,
      expiresInMinutes: 15,
    };

    if (options?.returnTokenForTesting && process.env.NODE_ENV === 'test') {
      response._testRecoveryToken = rawToken;
    }

    return response;
  } catch (error) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error requesting password recovery token:', error);
    throw new Error('Failed to process password recovery request.', { cause: error });
  }
}

/**
 * Verifies and atomically consumes a single-use password recovery token,
 * updates the user's password hash, and increments tokenVersion to revoke prior sessions.
 */
export async function confirmPasswordRecoveryToken(
  rawToken: string,
  newPassword: string
) {
  try {
    const cleanedToken = String(rawToken || '').trim();
    if (!cleanedToken || cleanedToken.length < 32) {
      throw new ClientSafeError(
        'Invalid or expired password recovery token.',
        400
      );
    }
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      throw new ClientSafeError(
        'New password must be at least 8 characters long.',
        400
      );
    }

    const tokenHash = hashRecoveryToken(cleanedToken);
    const now = new Date();
    const newPasswordHash = hashPassword(newPassword);

    const updatedUser = await db.transaction(async (tx) => {
      const tokenRows = await tx
        .select()
        .from(passwordResetTokens)
        .where(eq(passwordResetTokens.tokenHash, tokenHash));

      const tokenRecord = tokenRows[0];
      if (
        !tokenRecord ||
        tokenRecord.consumedAt !== null ||
        new Date(tokenRecord.expiresAt).getTime() <= now.getTime()
      ) {
        throw new ClientSafeError(
          'Invalid, expired, or already used password recovery token.',
          400
        );
      }

      // Atomic conditional consumption so concurrent requests with the same token cannot both succeed
      const consumedRows = await tx
        .update(passwordResetTokens)
        .set({ consumedAt: now })
        .where(
          and(
            eq(passwordResetTokens.id, tokenRecord.id),
            isNull(passwordResetTokens.consumedAt)
          )
        )
        .returning();

      if (consumedRows.length === 0) {
        throw new ClientSafeError(
          'Invalid, expired, or already used password recovery token.',
          400
        );
      }

      // Invalidate any other outstanding recovery tokens for this user
      await tx
        .update(passwordResetTokens)
        .set({ consumedAt: now })
        .where(
          and(
            eq(passwordResetTokens.userUid, tokenRecord.userUid),
            isNull(passwordResetTokens.consumedAt)
          )
        );

      const userRows = await tx
        .select()
        .from(users)
        .where(eq(users.uid, tokenRecord.userUid));
      const targetUser = userRows[0];

      if (!targetUser || targetUser.accountStatus !== 'active' || targetUser.deletedAt !== null) {
        throw new ClientSafeError('Account is no longer active.', 400);
      }

      const nextProvider =
        targetUser.authProvider === 'firebase' ? 'both' : targetUser.authProvider;

      const [updated] = await tx
        .update(users)
        .set({
          passwordHash: newPasswordHash,
          authProvider: nextProvider,
          tokenVersion: sql`${users.tokenVersion} + 1`,
          updatedAt: now,
        })
        .where(eq(users.uid, targetUser.uid))
        .returning();

      return updated;
    });

    return sanitizeUserForClient(updatedUser);
  } catch (error) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error confirming password recovery token:', error);
    throw new Error('Failed to reset password.', { cause: error });
  }
}

/**
 * Allows an authenticated user to change their existing password after verifying their current password.
 * Increments tokenVersion to invalidate older sessions.
 */
export async function changeAuthenticatedUserPassword(
  uid: string,
  currentPassword: string,
  newPassword: string
) {
  try {
    if (!currentPassword || typeof currentPassword !== 'string') {
      throw new ClientSafeError('Current password is required.', 400);
    }
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      throw new ClientSafeError('New password must be at least 8 characters long.', 400);
    }

    const rows = await db.select().from(users).where(eq(users.uid, uid));
    const user = rows[0];
    if (!user || user.accountStatus !== 'active') {
      throw new ClientSafeError('Account not found.', 404);
    }
    if (!user.passwordHash) {
      throw new ClientSafeError(
        'This account does not have a local password set yet. Use the link-password endpoint instead.',
        400
      );
    }
    if (!verifyPassword(currentPassword, user.passwordHash)) {
      throw new ClientSafeError('Current password is incorrect.', 401);
    }

    const [updated] = await db
      .update(users)
      .set({
        passwordHash: hashPassword(newPassword),
        tokenVersion: sql`${users.tokenVersion} + 1`,
        updatedAt: new Date(),
      })
      .where(eq(users.uid, uid))
      .returning();

    return updated;
  } catch (error) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error changing password:', error);
    throw new Error('Failed to change password.', { cause: error });
  }
}

/**
 * Allows an already-authenticated provider user (without a local password) to attach a local password
 * after proving account ownership via an authenticated session.
 */
export async function linkPasswordToAuthenticatedAccount(
  uid: string,
  newPassword: string
) {
  try {
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      throw new ClientSafeError('Password must be at least 8 characters long.', 400);
    }

    const rows = await db.select().from(users).where(eq(users.uid, uid));
    const user = rows[0];
    if (!user || user.accountStatus !== 'active') {
      throw new ClientSafeError('Account not found.', 404);
    }
    if (user.passwordHash) {
      throw new ClientSafeError(
        'A password is already configured for this account. Use change-password with your current password.',
        409
      );
    }

    const [updated] = await db
      .update(users)
      .set({
        passwordHash: hashPassword(newPassword),
        authProvider: 'both',
        tokenVersion: sql`${users.tokenVersion} + 1`,
        updatedAt: new Date(),
      })
      .where(eq(users.uid, uid))
      .returning();

    return updated;
  } catch (error) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error linking password to account:', error);
    throw new Error('Failed to link password to account.', { cause: error });
  }
}

/**
 * Increments a user's tokenVersion to immediately revoke all existing local session tokens.
 */
export async function revokeUserSessions(uid: string) {
  await db
    .update(users)
    .set({
      tokenVersion: sql`${users.tokenVersion} + 1`,
      updatedAt: new Date(),
    })
    .where(eq(users.uid, uid));
}

export async function updateUserProfile(
  uid: string,
  updates: { displayName?: string; preferences?: Record<string, unknown> }
) {
  try {
    const setData: Partial<typeof users.$inferInsert> = {
      updatedAt: new Date(),
    };
    if (updates.displayName && updates.displayName.trim()) {
      setData.displayName = updates.displayName.trim();
    }
    if (updates.preferences) {
      setData.preferences = JSON.stringify(updates.preferences);
    }
    // Notice role & subscriptionTier are NEVER modifiable here to prevent privilege escalation
    const [updated] = await db
      .update(users)
      .set(setData)
      .where(eq(users.uid, uid))
      .returning();
    if (!updated) {
      throw new ClientSafeError('User account not found.', 404);
    }
    return updated;
  } catch (error) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error updating user profile:', error);
    throw new Error('Failed to update user profile.', { cause: error });
  }
}

/**
 * Deletes a user account atomically inside a database transaction, records a tombstone
 * in deleted_accounts so existing tokens are immediately rejected and cannot resurrect the user,
 * and revokes Firebase refresh tokens best-effort.
 */
export async function deleteUserAccount(uid: string) {
  try {
    await db.transaction(async (tx) => {
      const existing = await tx.select().from(users).where(eq(users.uid, uid));
      const user = existing[0];
      const emailHash = user
        ? hashEmailForTombstone(user.email)
        : hashEmailForTombstone(uid);

      await tx
        .insert(deletedAccounts)
        .values({
          uid,
          emailHash,
          deletedAt: new Date(),
        })
        .onConflictDoNothing();

      await tx
        .delete(passwordResetTokens)
        .where(eq(passwordResetTokens.userUid, uid));
      await tx.delete(bookmarks).where(eq(bookmarks.userUid, uid));
      await tx
        .delete(questionAttempts)
        .where(eq(questionAttempts.userUid, uid));
      await tx.delete(examSessions).where(eq(examSessions.userUid, uid));
      await tx.delete(users).where(eq(users.uid, uid));
    });

    if (!uid.startsWith('usr_')) {
      try {
        await adminAuth.revokeRefreshTokens(uid);
      } catch {
        // Ignore if user does not exist in Firebase Auth or admin credentials are not configured for revocation
      }
    }

    return { deleted: true };
  } catch (error) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error deleting user account:', error);
    throw new Error('Failed to delete account records.', { cause: error });
  }
}

/**
 * Returns published subjects, lectures, and question counts for the public & student interfaces.
 * Draft and archived items are strictly filtered out at the database query level.
 */
export async function getPublishedCatalog() {
  try {
    await ensureSeededDatabase();
    const pubSubjects = await db
      .select()
      .from(subjects)
      .where(eq(subjects.status, 'published'))
      .orderBy(asc(subjects.displayOrder), asc(subjects.id));

    const pubLectures = await db
      .select()
      .from(lectures)
      .where(eq(lectures.status, 'published'))
      .orderBy(asc(lectures.lectureNumber), asc(lectures.id));

    const pubQuestions = await db
      .select()
      .from(questions)
      .where(eq(questions.status, 'published'));

    const pubBanks = await db
      .select()
      .from(questionBanks)
      .where(eq(questionBanks.status, 'published'));

    const subjSet = new Set(pubSubjects.map((s) => s.id));
    const visibleLectures = pubLectures.filter((l) => subjSet.has(l.subjectId));
    const lectSet = new Set(visibleLectures.map((l) => l.id));
    const visibleQuestions = pubQuestions.filter(
      (q) => subjSet.has(q.subjectId) && lectSet.has(q.lectureId)
    );

    const questionCountByLecture = new Map<number, number>();
    const questionCountBySubject = new Map<number, number>();
    const difficultyCountByLecture = new Map<
      number,
      { Easy: number; Medium: number; Hard: number }
    >();

    for (const q of visibleQuestions) {
      questionCountByLecture.set(
        q.lectureId,
        (questionCountByLecture.get(q.lectureId) || 0) + 1
      );
      questionCountBySubject.set(
        q.subjectId,
        (questionCountBySubject.get(q.subjectId) || 0) + 1
      );
      const diffCounts = difficultyCountByLecture.get(q.lectureId) || {
        Easy: 0,
        Medium: 0,
        Hard: 0,
      };
      if (q.difficulty === 'Easy' || q.difficulty === 'Medium' || q.difficulty === 'Hard') {
        diffCounts[q.difficulty]++;
      }
      difficultyCountByLecture.set(q.lectureId, diffCounts);
    }

    const enrichedLectures = visibleLectures.map((l) => {
      const parentSubj = pubSubjects.find((s) => s.id === l.subjectId);
      const banks = pubBanks.filter((b) => b.lectureId === l.id);
      return {
        ...l,
        subjectTitle: parentSubj?.title || 'Medical Subject',
        subjectSlug: parentSubj?.slug || '',
        questionCount: questionCountByLecture.get(l.id) || 0,
        difficultyBreakdown: difficultyCountByLecture.get(l.id) || {
          Easy: 0,
          Medium: 0,
          Hard: 0,
        },
        questionBanks: banks,
      };
    });

    const enrichedSubjects = pubSubjects.map((s) => {
      const subLectures = enrichedLectures.filter((l) => l.subjectId === s.id);
      return {
        ...s,
        lectureCount: subLectures.length,
        questionCount: questionCountBySubject.get(s.id) || 0,
        lectures: subLectures,
      };
    });

    return {
      subjects: enrichedSubjects,
      lectures: enrichedLectures,
      totalPublishedQuestions: visibleQuestions.length,
    };
  } catch (error) {
    console.error('Error fetching published catalog:', error);
    throw new Error('Failed to load educational catalog.', { cause: error });
  }
}

export interface SessionOrderItem {
  questionId: number;
  permutation: OptionPermutation;
  selectedDisplayed: OptionKey | null;
  selectedCanonical: OptionKey | null;
  submitted: boolean;
}

export interface ServerExamDeadlineStatus {
  serverElapsedSeconds: number;
  remainingSeconds: number | null;
  isExpired: boolean;
  isPastSubmissionGrace: boolean;
  effectiveElapsedSeconds: number;
}

/**
 * Pure server-side exam deadline evaluator.
 * Never trusts client-supplied elapsedSeconds for timed exam enforcement.
 */
export function evaluateServerExamDeadline(params: {
  mode: string;
  startedAt: Date | string;
  timeLimitSeconds: number | null;
  nowMs?: number;
  graceSeconds?: number;
}): ServerExamDeadlineStatus {
  const nowMs = params.nowMs ?? Date.now();
  const startedMs = new Date(params.startedAt).getTime();
  const serverElapsedSeconds = Math.max(
    0,
    Math.floor((nowMs - (Number.isFinite(startedMs) ? startedMs : nowMs)) / 1000)
  );

  if (params.timeLimitSeconds === null || params.mode !== 'exam') {
    return {
      serverElapsedSeconds,
      remainingSeconds: null,
      isExpired: false,
      isPastSubmissionGrace: false,
      effectiveElapsedSeconds: Math.max(1, serverElapsedSeconds),
    };
  }

  const limit = Math.max(1, params.timeLimitSeconds);
  const grace = Math.max(0, params.graceSeconds ?? EXAM_SUBMISSION_GRACE_SECONDS);
  const remainingSeconds = Math.max(0, limit - serverElapsedSeconds);
  const isExpired = serverElapsedSeconds > limit;
  const isPastSubmissionGrace = serverElapsedSeconds > limit + grace;
  const effectiveElapsedSeconds = Math.min(limit, Math.max(1, serverElapsedSeconds));

  return {
    serverElapsedSeconds,
    remainingSeconds,
    isExpired,
    isPastSubmissionGrace,
    effectiveElapsedSeconds,
  };
}

/**
 * Starts a new Study, Exam, or Custom Practice session for a specific authenticated student.
 */
export async function createPracticeOrExamSession(
  userUid: string,
  params: {
    mode: 'study' | 'exam' | 'custom';
    title?: string;
    subjectIds?: number[];
    lectureIds?: number[];
    difficulties?: DifficultyLevel[];
    tagFilter?: string;
    requestedCount?: number;
    shuffleQuestions?: boolean;
    shuffleOptions?: boolean;
    avoidRecent?: boolean;
    timeLimitMinutes?: number | null;
  }
) {
  try {
    await ensureSeededDatabase();
    const pubSubjects = await db
      .select()
      .from(subjects)
      .where(eq(subjects.status, 'published'));
    const pubLectures = await db
      .select()
      .from(lectures)
      .where(eq(lectures.status, 'published'));
    const pubQuestions = await db
      .select()
      .from(questions)
      .where(eq(questions.status, 'published'));

    const subjMap = new Map(pubSubjects.map((s) => [s.id, s]));
    const lectMap = new Map(pubLectures.map((l) => [l.id, l]));

    // Only include questions whose parent subject and lecture are ALSO published
    const eligiblePool = pubQuestions.filter(
      (q) => subjMap.has(q.subjectId) && lectMap.has(q.lectureId)
    );

    let recentlyAnsweredIds = new Set<number>();
    if (params.avoidRecent) {
      const recentAttempts = await db
        .select()
        .from(questionAttempts)
        .where(eq(questionAttempts.userUid, userUid))
        .orderBy(desc(questionAttempts.answeredAt))
        .limit(30);
      recentlyAnsweredIds = new Set(
        recentAttempts.map((a) => a.questionId).filter((id): id is number => id !== null)
      );
    }

    const selection = selectPracticeQuestions(eligiblePool, {
      subjectIds: params.subjectIds,
      lectureIds: params.lectureIds,
      difficulties: params.difficulties,
      tagFilter: params.tagFilter,
      requestedCount: params.requestedCount,
      shuffleQuestions: params.shuffleQuestions ?? params.mode !== 'study',
      recentlyAnsweredIds,
    });

    if (selection.selectedQuestions.length === 0) {
      throw new ClientSafeError(
        selection.shortfallNotice || 'No published questions match your selected filters.',
        400
      );
    }

    const orderItems: SessionOrderItem[] = selection.selectedQuestions.map((q, idx) => ({
      questionId: q.id,
      permutation: createOptionPermutation(
        Boolean(params.shuffleOptions),
        Date.now() + idx * 97 + q.id
      ),
      selectedDisplayed: null,
      selectedCanonical: null,
      submitted: false,
    }));

    const firstLect =
      params.lectureIds && params.lectureIds.length === 1
        ? lectMap.get(params.lectureIds[0])
        : null;
    const firstSubj =
      params.subjectIds && params.subjectIds.length === 1
        ? subjMap.get(params.subjectIds[0])
        : firstLect
        ? subjMap.get(firstLect.subjectId)
        : null;

    const defaultTitle =
      params.title ||
      (firstLect
        ? `${firstLect.title} (${params.mode === 'exam' ? 'Mock Exam' : 'Study'})`
        : firstSubj
        ? `${firstSubj.title} (${params.mode === 'exam' ? 'Mock Exam' : 'Practice'})`
        : `Custom Medical Practice (${selection.selectedQuestions.length} MCQs)`);

    const timeLimitSeconds =
      params.mode === 'exam'
        ? Math.max(
            60,
            Math.min(
              60 * 240,
              (params.timeLimitMinutes ??
                Math.max(5, selection.selectedQuestions.length * 2)) * 60
            )
          )
        : null;

    const [createdSession] = await db
      .insert(examSessions)
      .values({
        userUid,
        title: defaultTitle,
        mode: params.mode,
        subjectId: firstSubj?.id ?? null,
        lectureId: firstLect?.id ?? null,
        status: 'in_progress',
        totalQuestions: selection.selectedQuestions.length,
        correctCount: 0,
        incorrectCount: 0,
        unansweredCount: selection.selectedQuestions.length,
        scorePercentage: 0,
        timeLimitSeconds,
        elapsedSeconds: 0,
        shuffleOptions: Boolean(params.shuffleOptions),
        questionOrderJson: JSON.stringify(orderItems),
      })
      .returning();

    return {
      session: await getExamSessionForStudent(userUid, createdSession.id),
      shortfallNotice: selection.shortfallNotice,
    };
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error creating practice/exam session:', error);
    throw new Error('Failed to start question session.', { cause: error });
  }
}

/**
 * Retrieves an exam session for its owner student.
 * Strictly enforces userUid ownership so students can NEVER access another student's session.
 * During an active Exam Mode session, strips correct answers and explanations from the response!
 */
export async function getExamSessionForStudent(userUid: string, sessionId: number) {
  try {
    const rows = await db
      .select()
      .from(examSessions)
      .where(and(eq(examSessions.id, sessionId), eq(examSessions.userUid, userUid)));

    if (rows.length === 0) {
      throw new ClientSafeError(
        'Forbidden or not found: Exam session does not belong to this account.',
        403
      );
    }

    const session = rows[0];
    const orderItems: SessionOrderItem[] = JSON.parse(session.questionOrderJson || '[]');
    const qIds = orderItems.map((item) => item.questionId);

    const allQuestions =
      qIds.length > 0
        ? await db.select().from(questions).where(inArray(questions.id, qIds))
        : [];
    const allSubjects = await db.select().from(subjects);
    const allLectures = await db.select().from(lectures);

    const userBookmarks = await db
      .select()
      .from(bookmarks)
      .where(eq(bookmarks.userUid, userUid));
    const bookmarkedSet = new Set(userBookmarks.map((b) => b.questionId));

    const qMap = new Map(allQuestions.map((q) => [q.id, q]));
    const sMap = new Map(allSubjects.map((s) => [s.id, s.title]));
    const lMap = new Map(allLectures.map((l) => [l.id, l.title]));

    // If session is completed, also check saved historical attempts so snapshots are preserved
    const savedAttempts =
      session.status === 'completed'
        ? await db
            .select()
            .from(questionAttempts)
            .where(
              and(
                eq(questionAttempts.sessionId, session.id),
                eq(questionAttempts.userUid, userUid)
              )
            )
        : [];
    const attemptSnapshotMap = new Map<number, any>();
    for (const att of savedAttempts) {
      if (att.questionId !== null) {
        try {
          attemptSnapshotMap.set(att.questionId, JSON.parse(att.questionSnapshotJson));
        } catch {
          // fallback to live question
        }
      }
    }

    const isExamActive = session.mode === 'exam' && session.status === 'in_progress';

    const formattedQuestions = orderItems
      .map((item, idx) => {
        const snapshot = attemptSnapshotMap.get(item.questionId);
        const liveQ = qMap.get(item.questionId);
        const source = snapshot || liveQ;
        if (!source) return null;

        const canonicalQ: CanonicalQuestion = {
          id: item.questionId,
          subjectId: liveQ?.subjectId ?? 0,
          lectureId: liveQ?.lectureId ?? 0,
          subjectTitle:
            snapshot?.subjectTitle || (liveQ ? sMap.get(liveQ.subjectId) : 'Medical Subject'),
          lectureTitle:
            snapshot?.lectureTitle || (liveQ ? lMap.get(liveQ.lectureId) : 'Lecture'),
          questionText: source.questionText,
          optionA: source.optionA,
          optionB: source.optionB,
          optionC: source.optionC,
          optionD: source.optionD,
          correctAnswer: source.correctAnswer as OptionKey,
          explanation: source.explanation,
          explanationA: source.explanationA || '',
          explanationB: source.explanationB || '',
          explanationC: source.explanationC || '',
          explanationD: source.explanationD || '',
          difficulty: (source.difficulty || 'Medium') as DifficultyLevel,
          tags: source.tags || '',
          diagramSvg: source.diagramSvg || liveQ?.diagramSvg || '',
          status: (liveQ?.status || 'published') as ContentStatus,
        };

        // In Study or Custom mode, reveal answers only after the question is submitted (or session completed).
        // In Exam mode, NEVER reveal answers while session.status === 'in_progress'!
        const hideAnswers =
          isExamActive || (session.status === 'in_progress' && !item.submitted);

        const clientQ = formatQuestionForClient(canonicalQ, item.permutation, hideAnswers);
        return {
          ...clientQ,
          index: idx,
          selectedDisplayed: item.selectedDisplayed,
          submitted: item.submitted,
          isBookmarked: bookmarkedSet.has(item.questionId),
        };
      })
      .filter(Boolean);

    // Authoritative server-side remaining timer calculation for Exam Mode
    const deadlineStatus = evaluateServerExamDeadline({
      mode: session.mode,
      startedAt: session.startedAt,
      timeLimitSeconds: session.timeLimitSeconds,
    });

    const remainingSeconds =
      session.timeLimitSeconds !== null
        ? session.status === 'completed'
          ? Math.max(0, session.timeLimitSeconds - session.elapsedSeconds)
          : deadlineStatus.remainingSeconds
        : null;

    return {
      id: session.id,
      title: session.title,
      mode: session.mode,
      subjectId: session.subjectId,
      lectureId: session.lectureId,
      status: session.status,
      totalQuestions: session.totalQuestions,
      correctCount: session.correctCount,
      incorrectCount: session.incorrectCount,
      unansweredCount: session.unansweredCount,
      scorePercentage: session.scorePercentage,
      timeLimitSeconds: session.timeLimitSeconds,
      elapsedSeconds:
        session.status === 'completed'
          ? session.elapsedSeconds
          : deadlineStatus.serverElapsedSeconds,
      remainingSeconds,
      isExpired: session.status === 'in_progress' ? deadlineStatus.isExpired : false,
      shuffleOptions: session.shuffleOptions,
      startedAt: session.startedAt,
      completedAt: session.completedAt,
      questions: formattedQuestions,
    };
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error loading exam session:', error);
    throw new Error('Failed to load exam session.', { cause: error });
  }
}

/**
 * Records an answer selection for a single question inside a session.
 * Strictly enforces server-side exam deadlines and prevents modifying locked answers.
 */
export async function saveSessionQuestionAnswer(
  userUid: string,
  sessionId: number,
  questionId: number,
  displayedOption: OptionKey | null,
  lockAnswer: boolean,
  _clientElapsedSeconds?: number
) {
  try {
    if (
      displayedOption !== null &&
      displayedOption !== undefined &&
      !OPTION_KEYS.includes(displayedOption)
    ) {
      throw new ClientSafeError('Invalid answer option. Must be A, B, C, D, or null.', 400);
    }

    const rows = await db
      .select()
      .from(examSessions)
      .where(and(eq(examSessions.id, sessionId), eq(examSessions.userUid, userUid)));

    if (rows.length === 0) {
      throw new ClientSafeError('Forbidden: Session not found for this user.', 403);
    }

    const session = rows[0];
    if (session.status !== 'in_progress') {
      throw new ClientSafeError(
        'Cannot modify answers for a session that is already completed.',
        409
      );
    }

    const deadlineStatus = evaluateServerExamDeadline({
      mode: session.mode,
      startedAt: session.startedAt,
      timeLimitSeconds: session.timeLimitSeconds,
    });

    if (deadlineStatus.isExpired) {
      throw new ClientSafeError(
        'Exam time limit has expired. Further answer modifications are not allowed.',
        409
      );
    }

    const orderItems: SessionOrderItem[] = JSON.parse(session.questionOrderJson || '[]');
    const targetItem = orderItems.find((item) => item.questionId === questionId);
    if (!targetItem) {
      throw new ClientSafeError('Question does not belong to this session.', 400);
    }

    // In Study or Custom mode, once a question is locked/submitted and its explanation revealed,
    // prevent overwriting the submitted answer.
    if (session.mode !== 'exam' && targetItem.submitted) {
      return getExamSessionForStudent(userUid, sessionId);
    }

    targetItem.selectedDisplayed = displayedOption ?? null;
    targetItem.selectedCanonical = resolveCanonicalOption(
      displayedOption ?? null,
      targetItem.permutation
    );
    if (lockAnswer) {
      targetItem.submitted = true;
    }

    await db
      .update(examSessions)
      .set({
        questionOrderJson: JSON.stringify(orderItems),
        elapsedSeconds: Math.max(
          session.elapsedSeconds,
          deadlineStatus.effectiveElapsedSeconds
        ),
      })
      .where(
        and(
          eq(examSessions.id, sessionId),
          eq(examSessions.userUid, userUid),
          eq(examSessions.status, 'in_progress')
        )
      );

    return getExamSessionForStudent(userUid, sessionId);
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error saving question answer:', error);
    throw new Error('Failed to save question response.', { cause: error });
  }
}

/**
 * Completes and grades an Exam or Study session atomically and idempotently inside a PostgreSQL transaction.
 * - Acquires a row-level lock (FOR UPDATE) on the session row so concurrent completion requests cannot race.
 * - Computes authoritative elapsed time from server timestamps (never trusting manipulated clientElapsedSeconds).
 * - Rejects post-deadline answer modifications in timed Exam Mode.
 * - Uses unique index protection on (session_id, question_id) in question_attempts.
 */
export async function completeExamSession(
  userUid: string,
  sessionId: number,
  finalDisplayedAnswers?: Record<number, OptionKey | null>,
  _clientElapsedSeconds?: number
) {
  try {
    await db.transaction(async (tx) => {
      // Acquire row-level lock on the exam session row to serialize concurrent completion calls
      await tx.execute(
        sql`SELECT id, status FROM exam_sessions WHERE id = ${sessionId} AND user_uid = ${userUid} FOR UPDATE`
      );

      const rows = await tx
        .select()
        .from(examSessions)
        .where(and(eq(examSessions.id, sessionId), eq(examSessions.userUid, userUid)));

      if (rows.length === 0) {
        throw new ClientSafeError('Forbidden: Session not found for this user.', 403);
      }

      const session = rows[0];
      if (session.status === 'completed') {
        return;
      }

      const deadlineStatus = evaluateServerExamDeadline({
        mode: session.mode,
        startedAt: session.startedAt,
        timeLimitSeconds: session.timeLimitSeconds,
      });

      const orderItems: SessionOrderItem[] = JSON.parse(session.questionOrderJson || '[]');

      if (finalDisplayedAnswers && typeof finalDisplayedAnswers === 'object') {
        // Check if client is attempting to alter answers after the server deadline expired
        if (deadlineStatus.isExpired) {
          let attemptedPostExpiryMutation = false;
          for (const item of orderItems) {
            if (item.questionId in finalDisplayedAnswers) {
              const disp = finalDisplayedAnswers[item.questionId] ?? null;
              if (disp !== item.selectedDisplayed) {
                attemptedPostExpiryMutation = true;
                break;
              }
            }
          }
          if (attemptedPostExpiryMutation && deadlineStatus.isPastSubmissionGrace) {
            throw new ClientSafeError(
              'Exam deadline has expired. Late answer modifications were rejected.',
              409
            );
          }
          // Even within auto-submit grace, if the deadline has passed, grade only answers already saved before expiry
          for (const item of orderItems) {
            item.submitted = true;
          }
        } else {
          for (const item of orderItems) {
            if (item.questionId in finalDisplayedAnswers) {
              const rawDisp = finalDisplayedAnswers[item.questionId];
              const validDisp =
                rawDisp && OPTION_KEYS.includes(rawDisp) ? rawDisp : null;
              item.selectedDisplayed = validDisp;
              item.selectedCanonical = resolveCanonicalOption(
                validDisp,
                item.permutation
              );
            }
            item.submitted = true;
          }
        }
      } else {
        for (const item of orderItems) {
          item.submitted = true;
        }
      }

      const qIds = orderItems.map((i) => i.questionId);
      const dbQuestions =
        qIds.length > 0
          ? await tx.select().from(questions).where(inArray(questions.id, qIds))
          : [];
      const allSubjects = await tx.select().from(subjects);
      const allLectures = await tx.select().from(lectures);

      const qMap = new Map(dbQuestions.map((q) => [q.id, q]));
      const sMap = new Map(allSubjects.map((s) => [s.id, s.title]));
      const lMap = new Map(allLectures.map((l) => [l.id, l.title]));

      const canonicalAnswersMap: Record<number, OptionKey | null> = {};
      const questionsForScoring: Array<{ id: number; correctAnswer: OptionKey }> = [];

      for (const item of orderItems) {
        const q = qMap.get(item.questionId);
        if (q) {
          questionsForScoring.push({
            id: q.id,
            correctAnswer: q.correctAnswer as OptionKey,
          });
          canonicalAnswersMap[q.id] = item.selectedCanonical;
        }
      }

      const score = scoreExamSession(questionsForScoring, canonicalAnswersMap);
      const finalElapsed = deadlineStatus.effectiveElapsedSeconds;

      // Conditional status transition from 'in_progress' -> 'completed'
      const updatedSessions = await tx
        .update(examSessions)
        .set({
          status: 'completed',
          correctCount: score.correctCount,
          incorrectCount: score.incorrectCount,
          unansweredCount: score.unansweredCount,
          scorePercentage: score.scorePercentage,
          elapsedSeconds: finalElapsed,
          questionOrderJson: JSON.stringify(orderItems),
          completedAt: new Date(),
        })
        .where(
          and(
            eq(examSessions.id, sessionId),
            eq(examSessions.userUid, userUid),
            eq(examSessions.status, 'in_progress')
          )
        )
        .returning();

      if (updatedSessions.length === 0) {
        return;
      }

      await tx
        .delete(questionAttempts)
        .where(
          and(
            eq(questionAttempts.sessionId, sessionId),
            eq(questionAttempts.userUid, userUid)
          )
        );

      const avgTimePerQ =
        score.totalQuestions > 0 ? Math.round(finalElapsed / score.totalQuestions) : 0;

      for (const res of score.questionResults) {
        const q = qMap.get(res.questionId);
        if (!q) continue;

        const snapshotJson = JSON.stringify({
          id: q.id,
          subjectTitle: sMap.get(q.subjectId) || 'Medical Subject',
          lectureTitle: lMap.get(q.lectureId) || 'Lecture',
          questionText: q.questionText,
          optionA: q.optionA,
          optionB: q.optionB,
          optionC: q.optionC,
          optionD: q.optionD,
          correctAnswer: q.correctAnswer,
          explanation: q.explanation,
          explanationA: q.explanationA,
          explanationB: q.explanationB,
          explanationC: q.explanationC,
          explanationD: q.explanationD,
          difficulty: q.difficulty,
          tags: q.tags,
          version: q.version,
        });

        await tx
          .insert(questionAttempts)
          .values({
            sessionId,
            userUid,
            questionId: q.id,
            subjectId: q.subjectId,
            lectureId: q.lectureId,
            selectedOption: res.selectedCanonical,
            correctOptionSnapshot: res.correctCanonical,
            isCorrect: res.isCorrect,
            questionSnapshotJson: snapshotJson,
            timeSpentSeconds: avgTimePerQ,
          })
          .onConflictDoNothing();
      }
    });

    return getExamSessionForStudent(userUid, sessionId);
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error completing exam session:', error);
    throw new Error('Failed to submit and grade exam session.', { cause: error });
  }
}

/**
 * Bookmarks management (private to each student)
 */
export async function toggleBookmarkForStudent(
  userUid: string,
  questionId: number,
  note?: string
) {
  try {
    const existing = await db
      .select()
      .from(bookmarks)
      .where(and(eq(bookmarks.userUid, userUid), eq(bookmarks.questionId, questionId)));

    if (existing.length > 0) {
      await db
        .delete(bookmarks)
        .where(and(eq(bookmarks.userUid, userUid), eq(bookmarks.questionId, questionId)));
      return { bookmarked: false, questionId };
    }

    await db.insert(bookmarks).values({
      userUid,
      questionId,
      note: note?.trim() || '',
    });
    return { bookmarked: true, questionId };
  } catch (error) {
    console.error('Error toggling bookmark:', error);
    throw new Error('Failed to update question bookmark.', { cause: error });
  }
}

export async function getStudentBookmarksAndReview(userUid: string) {
  try {
    await ensureSeededDatabase();
    const userBookmarks = await db
      .select()
      .from(bookmarks)
      .where(eq(bookmarks.userUid, userUid))
      .orderBy(desc(bookmarks.createdAt));

    const userAttempts = await db
      .select()
      .from(questionAttempts)
      .where(eq(questionAttempts.userUid, userUid))
      .orderBy(desc(questionAttempts.answeredAt));

    const allQuestions = await db
      .select()
      .from(questions)
      .where(eq(questions.status, 'published'));
    const allSubjects = await db.select().from(subjects);
    const allLectures = await db.select().from(lectures);

    const qMap = new Map(allQuestions.map((q) => [q.id, q]));
    const sMap = new Map(allSubjects.map((s) => [s.id, s.title]));
    const lMap = new Map(allLectures.map((l) => [l.id, l.title]));

    const latestAttemptByQuestion = new Map<
      number,
      { selectedOption: string | null; isCorrect: boolean; answeredAt: Date }
    >();
    for (const att of userAttempts) {
      if (att.questionId !== null && !latestAttemptByQuestion.has(att.questionId)) {
        latestAttemptByQuestion.set(att.questionId, {
          selectedOption: att.selectedOption,
          isCorrect: att.isCorrect,
          answeredAt: att.answeredAt,
        });
      }
    }

    const bookmarkedItems = userBookmarks
      .map((b) => {
        const q = qMap.get(b.questionId);
        if (!q) return null;
        const latestAtt = latestAttemptByQuestion.get(q.id);
        return {
          bookmarkId: b.id,
          bookmarkedAt: b.createdAt,
          note: b.note,
          questionId: q.id,
          subjectId: q.subjectId,
          lectureId: q.lectureId,
          subjectTitle: sMap.get(q.subjectId) || 'Subject',
          lectureTitle: lMap.get(q.lectureId) || 'Lecture',
          questionText: q.questionText,
          optionA: q.optionA,
          optionB: q.optionB,
          optionC: q.optionC,
          optionD: q.optionD,
          correctAnswer: q.correctAnswer,
          explanation: q.explanation,
          explanationA: q.explanationA,
          explanationB: q.explanationB,
          explanationC: q.explanationC,
          explanationD: q.explanationD,
          difficulty: q.difficulty,
          tags: q.tags,
          diagramSvg: q.diagramSvg,
          lastAttemptStatus: !latestAtt
            ? 'unanswered'
            : latestAtt.selectedOption === null
            ? 'unanswered'
            : latestAtt.isCorrect
            ? 'correct'
            : 'incorrect',
          lastSelectedOption: latestAtt?.selectedOption ?? null,
        };
      })
      .filter(Boolean);

    const bookmarkedIds = new Set(userBookmarks.map((b) => b.questionId));
    const answeredReviewItems = Array.from(latestAttemptByQuestion.entries())
      .map(([questionId, latestAtt]) => {
        const q = qMap.get(questionId);
        if (!q) return null;
        return {
          questionId: q.id,
          subjectId: q.subjectId,
          lectureId: q.lectureId,
          subjectTitle: sMap.get(q.subjectId) || 'Subject',
          lectureTitle: lMap.get(q.lectureId) || 'Lecture',
          questionText: q.questionText,
          optionA: q.optionA,
          optionB: q.optionB,
          optionC: q.optionC,
          optionD: q.optionD,
          correctAnswer: q.correctAnswer,
          explanation: q.explanation,
          explanationA: q.explanationA,
          explanationB: q.explanationB,
          explanationC: q.explanationC,
          explanationD: q.explanationD,
          difficulty: q.difficulty,
          tags: q.tags,
          diagramSvg: q.diagramSvg,
          isBookmarked: bookmarkedIds.has(q.id),
          status:
            latestAtt.selectedOption === null
              ? 'unanswered'
              : latestAtt.isCorrect
              ? 'correct'
              : 'incorrect',
          selectedOption: latestAtt.selectedOption,
          answeredAt: latestAtt.answeredAt,
        };
      })
      .filter(Boolean);

    return {
      bookmarks: bookmarkedItems,
      answeredQuestions: answeredReviewItems,
    };
  } catch (error) {
    console.error('Error fetching student bookmarks:', error);
    throw new Error('Failed to load bookmarks and review history.', { cause: error });
  }
}

/**
 * Student Dashboard & Progress Analytics using real database records.
 * Clearly distinguishes between unique questions attempted and total answers submitted.
 */
export async function getStudentDashboardAnalytics(userUid: string) {
  try {
    await ensureSeededDatabase();
    const userSessions = await db
      .select()
      .from(examSessions)
      .where(eq(examSessions.userUid, userUid))
      .orderBy(desc(examSessions.startedAt));

    const userAttempts = await db
      .select()
      .from(questionAttempts)
      .where(eq(questionAttempts.userUid, userUid))
      .orderBy(desc(questionAttempts.answeredAt));

    const userBookmarks = await db
      .select()
      .from(bookmarks)
      .where(eq(bookmarks.userUid, userUid));

    const allSubjects = await db
      .select()
      .from(subjects)
      .where(eq(subjects.status, 'published'))
      .orderBy(asc(subjects.displayOrder));
    const allLectures = await db
      .select()
      .from(lectures)
      .where(eq(lectures.status, 'published'))
      .orderBy(asc(lectures.lectureNumber));
    const allQuestions = await db
      .select()
      .from(questions)
      .where(eq(questions.status, 'published'));

    const completedSessions = userSessions.filter((s) => s.status === 'completed');
    const inProgressSessions = userSessions.filter((s) => s.status === 'in_progress');

    const answeredAttempts = userAttempts.filter((a) => a.selectedOption !== null);
    const totalAnswersSubmitted = answeredAttempts.length;
    const totalCorrectAnswers = answeredAttempts.filter((a) => a.isCorrect).length;
    const overallAccuracy =
      totalAnswersSubmitted > 0
        ? Math.round((totalCorrectAnswers / totalAnswersSubmitted) * 100)
        : 0;

    const uniqueQuestionIds = new Set(
      answeredAttempts.map((a) => a.questionId).filter((id): id is number => id !== null)
    );
    const uniqueLecturesAttempted = new Set(
      answeredAttempts.map((a) => a.lectureId).filter((id): id is number => id !== null)
    );

    // Subject & Lecture breakdown (unique vs total answers submitted)
    const subjectProgress = allSubjects.map((subj) => {
      const subjQuestions = allQuestions.filter((q) => q.subjectId === subj.id);
      const subjAttempts = answeredAttempts.filter((a) => a.subjectId === subj.id);
      const subjUniqueIds = new Set(
        subjAttempts.map((a) => a.questionId).filter((id): id is number => id !== null)
      );
      const subjCorrect = subjAttempts.filter((a) => a.isCorrect).length;
      const accuracy =
        subjAttempts.length > 0 ? Math.round((subjCorrect / subjAttempts.length) * 100) : 0;
      const latestAttempt = subjAttempts[0]?.answeredAt ?? null;

      const lectureBreakdown = allLectures
        .filter((l) => l.subjectId === subj.id)
        .map((lect) => {
          const lectQuestions = subjQuestions.filter((q) => q.lectureId === lect.id);
          const lectAttempts = subjAttempts.filter((a) => a.lectureId === lect.id);
          const lectUniqueIds = new Set(
            lectAttempts.map((a) => a.questionId).filter((id): id is number => id !== null)
          );
          const lectCorrect = lectAttempts.filter((a) => a.isCorrect).length;
          return {
            lectureId: lect.id,
            title: lect.title,
            totalPublishedQuestions: lectQuestions.length,
            uniqueQuestionsAttempted: lectUniqueIds.size,
            totalAnswersSubmitted: lectAttempts.length,
            correctAnswers: lectCorrect,
            accuracyPercentage:
              lectAttempts.length > 0
                ? Math.round((lectCorrect / lectAttempts.length) * 100)
                : 0,
            lastAttemptAt: lectAttempts[0]?.answeredAt ?? null,
          };
        });

      return {
        subjectId: subj.id,
        title: subj.title,
        totalPublishedQuestions: subjQuestions.length,
        uniqueQuestionsAttempted: subjUniqueIds.size,
        totalAnswersSubmitted: subjAttempts.length,
        correctAnswers: subjCorrect,
        accuracyPercentage: accuracy,
        lastAttemptAt: latestAttempt,
        lectures: lectureBreakdown,
      };
    });

    // Weak-topic analysis with small-sample transparency
    const attemptsWithTags = answeredAttempts.map((att) => {
      let tags = '';
      try {
        const snap = JSON.parse(att.questionSnapshotJson);
        tags = snap.tags || '';
      } catch {
        const liveQ = allQuestions.find((q) => q.id === att.questionId);
        tags = liveQ?.tags || '';
      }
      return {
        questionId: att.questionId,
        isCorrect: att.isCorrect,
        tags,
      };
    });

    const topicPerformance = computeTopicPerformance(attemptsWithTags);

    const sMap = new Map(allSubjects.map((s) => [s.id, s.title]));
    const lMap = new Map(allLectures.map((l) => [l.id, l.title]));

    const history = userSessions.map((s) => ({
      id: s.id,
      title: s.title,
      mode: s.mode,
      status: s.status,
      subjectTitle: s.subjectId ? sMap.get(s.subjectId) || 'Multi-Subject' : 'Multi-Subject',
      lectureTitle: s.lectureId ? lMap.get(s.lectureId) || 'All Lectures' : 'Multiple Lectures',
      totalQuestions: s.totalQuestions,
      correctCount: s.correctCount,
      incorrectCount: s.incorrectCount,
      unansweredCount: s.unansweredCount,
      scorePercentage: s.scorePercentage,
      elapsedSeconds: s.elapsedSeconds,
      startedAt: s.startedAt,
      completedAt: s.completedAt,
    }));

    return {
      summary: {
        totalCompletedAttempts: completedSessions.length,
        inProgressCount: inProgressSessions.length,
        totalQuestionsAnswered: totalAnswersSubmitted,
        uniqueQuestionsAttempted: uniqueQuestionIds.size,
        totalPublishedQuestions: allQuestions.length,
        overallAccuracy,
        lecturesAttemptedCount: uniqueLecturesAttempted.size,
        totalPublishedLectures: allLectures.length,
        bookmarkCount: userBookmarks.length,
      },
      subjectProgress,
      topicPerformance,
      history,
    };
  } catch (error) {
    console.error('Error building student dashboard analytics:', error);
    throw new Error('Failed to load student progress analytics.', { cause: error });
  }
}

/**
 * ADMINISTRATOR REPOSITORY OPERATIONS
 * Every admin operation logs to adminAuditLogs and preserves historical attempts.
 */
export async function logAdminAction(
  adminUid: string,
  adminEmail: string,
  action: string,
  targetType: string,
  targetId: string | number,
  details: string
) {
  try {
    await db.insert(adminAuditLogs).values({
      adminUid,
      adminEmail,
      action,
      targetType,
      targetId: String(targetId),
      details,
    });
  } catch (error) {
    console.error('Failed to write admin audit log:', error);
  }
}

export async function getAdminDashboardData() {
  try {
    await ensureSeededDatabase();
    const allUsers = await db.select().from(users).orderBy(desc(users.createdAt));
    const allSubjects = await db
      .select()
      .from(subjects)
      .orderBy(asc(subjects.displayOrder), asc(subjects.id));
    const allLectures = await db
      .select()
      .from(lectures)
      .orderBy(asc(lectures.subjectId), asc(lectures.lectureNumber));
    const allBanks = await db.select().from(questionBanks);
    const allQuestions = await db
      .select()
      .from(questions)
      .orderBy(desc(questions.updatedAt), desc(questions.id));
    const recentSessions = await db
      .select()
      .from(examSessions)
      .orderBy(desc(examSessions.startedAt))
      .limit(15);
    const recentImports = await db
      .select()
      .from(importBatches)
      .orderBy(desc(importBatches.createdAt))
      .limit(10);
    const recentAuditLogs = await db
      .select()
      .from(adminAuditLogs)
      .orderBy(desc(adminAuditLogs.createdAt))
      .limit(25);

    const sMap = new Map(allSubjects.map((s) => [s.id, s.title]));
    const lMap = new Map(allLectures.map((l) => [l.id, l.title]));

    return {
      metrics: {
        totalUsers: allUsers.length,
        publishedSubjects: allSubjects.filter((s) => s.status === 'published').length,
        totalSubjects: allSubjects.length,
        publishedLectures: allLectures.filter((l) => l.status === 'published').length,
        totalLectures: allLectures.length,
        publishedQuestions: allQuestions.filter((q) => q.status === 'published').length,
        totalQuestions: allQuestions.length,
        completedExamsCount: recentSessions.filter((s) => s.status === 'completed').length,
      },
      subjects: allSubjects.map((s) => ({
        ...s,
        lectureCount: allLectures.filter((l) => l.subjectId === s.id).length,
        questionCount: allQuestions.filter((q) => q.subjectId === s.id).length,
      })),
      lectures: allLectures.map((l) => ({
        ...l,
        subjectTitle: sMap.get(l.subjectId) || 'Unknown Subject',
        questionCount: allQuestions.filter((q) => q.lectureId === l.id).length,
      })),
      questionBanks: allBanks.map((b) => ({
        ...b,
        subjectTitle: sMap.get(b.subjectId) || 'Unknown Subject',
        lectureTitle: b.lectureId ? lMap.get(b.lectureId) || 'Unknown Lecture' : 'All Lectures',
        questionCount: allQuestions.filter(
          (q) => q.questionBankId === b.id || (b.lectureId && q.lectureId === b.lectureId)
        ).length,
      })),
      questions: allQuestions.map((q) => ({
        ...q,
        subjectTitle: sMap.get(q.subjectId) || 'Unknown Subject',
        lectureTitle: lMap.get(q.lectureId) || 'Unknown Lecture',
      })),
      users: allUsers.map(({ passwordHash: _ph, ...u }) => ({
        ...u,
        isOwner: isOwnerAdminEmail(u.email),
      })),
      recentActivity: recentSessions,
      recentImports,
      auditLogs: recentAuditLogs,
    };
  } catch (error) {
    console.error('Error loading admin dashboard:', error);
    throw new Error('Failed to load administrator console data.', { cause: error });
  }
}

export async function upsertSubjectAdmin(
  admin: { uid: string; email: string },
  payload: {
    id?: number;
    title: string;
    description: string;
    displayOrder: number;
    status: ContentStatus;
  }
) {
  try {
    const slug = payload.title
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');

    if (payload.id) {
      const [updated] = await db
        .update(subjects)
        .set({
          title: payload.title.trim(),
          description: payload.description.trim(),
          displayOrder: Number(payload.displayOrder) || 1,
          status: payload.status,
          updatedAt: new Date(),
        })
        .where(eq(subjects.id, payload.id))
        .returning();

      await logAdminAction(
        admin.uid,
        admin.email,
        'UPDATE_SUBJECT',
        'subject',
        updated.id,
        `Updated subject "${updated.title}" (status: ${updated.status})`
      );
      return updated;
    }

    const [created] = await db
      .insert(subjects)
      .values({
        slug: `${slug}-${Date.now().toString(36)}`,
        title: payload.title.trim(),
        description: payload.description.trim(),
        displayOrder: Number(payload.displayOrder) || 1,
        status: payload.status || 'published',
      })
      .returning();

    await logAdminAction(
      admin.uid,
      admin.email,
      'CREATE_SUBJECT',
      'subject',
      created.id,
      `Created subject "${created.title}"`
    );
    return created;
  } catch (error) {
    console.error('Error saving subject:', error);
    throw new Error('Failed to save subject.', { cause: error });
  }
}

export async function upsertLectureAdmin(
  admin: { uid: string; email: string },
  payload: {
    id?: number;
    subjectId: number;
    title: string;
    description: string;
    lectureNumber: number;
    educationalNotes?: string;
    estimatedMinutes?: number;
    status: ContentStatus;
  }
) {
  try {
    if (payload.id) {
      const [updated] = await db
        .update(lectures)
        .set({
          subjectId: Number(payload.subjectId),
          title: payload.title.trim(),
          description: payload.description.trim(),
          lectureNumber: Number(payload.lectureNumber) || 1,
          educationalNotes: payload.educationalNotes?.trim() || '',
          estimatedMinutes: Number(payload.estimatedMinutes) || 30,
          status: payload.status,
          updatedAt: new Date(),
        })
        .where(eq(lectures.id, payload.id))
        .returning();

      await logAdminAction(
        admin.uid,
        admin.email,
        'UPDATE_LECTURE',
        'lecture',
        updated.id,
        `Updated lecture "${updated.title}" (status: ${updated.status})`
      );
      return updated;
    }

    const created = await db.transaction(async (tx) => {
      const [insertedLecture] = await tx
        .insert(lectures)
        .values({
          subjectId: Number(payload.subjectId),
          title: payload.title.trim(),
          description: payload.description.trim(),
          lectureNumber: Number(payload.lectureNumber) || 1,
          educationalNotes: payload.educationalNotes?.trim() || '',
          estimatedMinutes: Number(payload.estimatedMinutes) || 30,
          status: payload.status || 'published',
        })
        .returning();

      // Automatically create a default Practice Question Bank for the new lecture
      await tx.insert(questionBanks).values({
        subjectId: insertedLecture.subjectId,
        lectureId: insertedLecture.id,
        title: `${insertedLecture.title} — Practice Bank`,
        description: `Formative practice bank for ${insertedLecture.title}.`,
        bankType: 'practice',
        status: 'published',
      });

      return insertedLecture;
    });

    await logAdminAction(
      admin.uid,
      admin.email,
      'CREATE_LECTURE',
      'lecture',
      created.id,
      `Created lecture "${created.title}"`
    );
    return created;
  } catch (error) {
    console.error('Error saving lecture:', error);
    throw new Error('Failed to save lecture.', { cause: error });
  }
}

export async function upsertQuestionAdmin(
  admin: { uid: string; email: string },
  payload: {
    id?: number;
    subjectId: number;
    lectureId: number;
    questionText: string;
    optionA: string;
    optionB: string;
    optionC: string;
    optionD: string;
    correctAnswer: OptionKey;
    explanation: string;
    explanationA?: string;
    explanationB?: string;
    explanationC?: string;
    explanationD?: string;
    difficulty: DifficultyLevel;
    tags?: string;
    status: ContentStatus;
  }
) {
  try {
    const contentHash = computeContentHash(
      `${payload.subjectId}|${payload.lectureId}|${payload.questionText}|${payload.optionA}|${payload.optionB}|${payload.optionC}|${payload.optionD}`
    );

    if (payload.id) {
      const existing = await db
        .select()
        .from(questions)
        .where(eq(questions.id, payload.id));
      const nextVersion = (existing[0]?.version || 1) + 1;

      const [updated] = await db
        .update(questions)
        .set({
          subjectId: Number(payload.subjectId),
          lectureId: Number(payload.lectureId),
          questionText: payload.questionText.trim(),
          optionA: payload.optionA.trim(),
          optionB: payload.optionB.trim(),
          optionC: payload.optionC.trim(),
          optionD: payload.optionD.trim(),
          correctAnswer: payload.correctAnswer,
          explanation: payload.explanation.trim(),
          explanationA: payload.explanationA?.trim() || '',
          explanationB: payload.explanationB?.trim() || '',
          explanationC: payload.explanationC?.trim() || '',
          explanationD: payload.explanationD?.trim() || '',
          difficulty: payload.difficulty,
          tags: payload.tags?.trim() || '',
          status: payload.status,
          version: nextVersion,
          contentHash,
          updatedAt: new Date(),
        })
        .where(eq(questions.id, payload.id))
        .returning();

      await logAdminAction(
        admin.uid,
        admin.email,
        'UPDATE_QUESTION',
        'question',
        updated.id,
        `Updated question #${updated.id} to v${nextVersion} (historical attempt snapshots remain untouched)`
      );
      return updated;
    }

    const [created] = await db
      .insert(questions)
      .values({
        subjectId: Number(payload.subjectId),
        lectureId: Number(payload.lectureId),
        questionText: payload.questionText.trim(),
        optionA: payload.optionA.trim(),
        optionB: payload.optionB.trim(),
        optionC: payload.optionC.trim(),
        optionD: payload.optionD.trim(),
        correctAnswer: payload.correctAnswer,
        explanation: payload.explanation.trim(),
        explanationA: payload.explanationA?.trim() || '',
        explanationB: payload.explanationB?.trim() || '',
        explanationC: payload.explanationC?.trim() || '',
        explanationD: payload.explanationD?.trim() || '',
        difficulty: payload.difficulty,
        tags: payload.tags?.trim() || '',
        status: payload.status || 'published',
        version: 1,
        contentHash,
      })
      .returning();

    await logAdminAction(
      admin.uid,
      admin.email,
      'CREATE_QUESTION',
      'question',
      created.id,
      `Created question #${created.id} (${created.difficulty})`
    );
    return created;
  } catch (error) {
    console.error('Error saving question:', error);
    throw new Error('Failed to save question.', { cause: error });
  }
}

/**
 * Permanently deletes a Subject and all its Lectures, Question Banks (Quizzes),
 * Questions, Bookmarks, Question Attempts, and Exam Sessions atomically.
 */
export async function deleteSubjectAdmin(
  admin: { uid: string; email: string },
  subjectId: number
) {
  try {
    const { title, qCount } = await db.transaction(async (tx) => {
      const existing = await tx
        .select()
        .from(subjects)
        .where(eq(subjects.id, subjectId));
      const subjTitle = existing[0]?.title || `Subject #${subjectId}`;

      const subjectQuestions = await tx
        .select({ id: questions.id })
        .from(questions)
        .where(eq(questions.subjectId, subjectId));
      const qIds = subjectQuestions.map((q) => q.id);

      if (qIds.length > 0) {
        await tx.delete(bookmarks).where(inArray(bookmarks.questionId, qIds));
        await tx
          .delete(questionAttempts)
          .where(inArray(questionAttempts.questionId, qIds));
      }

      await tx
        .delete(questionAttempts)
        .where(eq(questionAttempts.subjectId, subjectId));
      await tx.delete(examSessions).where(eq(examSessions.subjectId, subjectId));
      await tx.delete(questions).where(eq(questions.subjectId, subjectId));
      await tx.delete(questionBanks).where(eq(questionBanks.subjectId, subjectId));
      await tx.delete(lectures).where(eq(lectures.subjectId, subjectId));
      await tx.delete(subjects).where(eq(subjects.id, subjectId));

      return { title: subjTitle, qCount: qIds.length };
    });

    await logAdminAction(
      admin.uid,
      admin.email,
      'DELETE_SUBJECT',
      'subject',
      subjectId,
      `Permanently deleted subject "${title}" and all its lectures, quizzes, and ${qCount} question(s).`
    );

    return {
      action: 'deleted',
      message: `Subject "${title}" and all associated lectures, quizzes, and questions were permanently deleted.`,
    };
  } catch (error) {
    console.error('Error deleting subject:', error);
    throw new Error('Failed to delete subject.', { cause: error });
  }
}

/**
 * Permanently deletes a Lecture and all its Question Banks (Quizzes),
 * Questions, Bookmarks, Question Attempts, and Exam Sessions atomically.
 */
export async function deleteLectureAdmin(
  admin: { uid: string; email: string },
  lectureId: number
) {
  try {
    const { title, qCount } = await db.transaction(async (tx) => {
      const existing = await tx
        .select()
        .from(lectures)
        .where(eq(lectures.id, lectureId));
      const lectTitle = existing[0]?.title || `Lecture #${lectureId}`;

      const lectureQuestions = await tx
        .select({ id: questions.id })
        .from(questions)
        .where(eq(questions.lectureId, lectureId));
      const qIds = lectureQuestions.map((q) => q.id);

      if (qIds.length > 0) {
        await tx.delete(bookmarks).where(inArray(bookmarks.questionId, qIds));
        await tx
          .delete(questionAttempts)
          .where(inArray(questionAttempts.questionId, qIds));
      }

      await tx
        .delete(questionAttempts)
        .where(eq(questionAttempts.lectureId, lectureId));
      await tx.delete(examSessions).where(eq(examSessions.lectureId, lectureId));
      await tx.delete(questions).where(eq(questions.lectureId, lectureId));
      await tx.delete(questionBanks).where(eq(questionBanks.lectureId, lectureId));
      await tx.delete(lectures).where(eq(lectures.id, lectureId));

      return { title: lectTitle, qCount: qIds.length };
    });

    await logAdminAction(
      admin.uid,
      admin.email,
      'DELETE_LECTURE',
      'lecture',
      lectureId,
      `Permanently deleted lecture "${title}" and all its quizzes and ${qCount} question(s).`
    );

    return {
      action: 'deleted',
      message: `Lecture "${title}" and all associated quizzes and questions were permanently deleted.`,
    };
  } catch (error) {
    console.error('Error deleting lecture:', error);
    throw new Error('Failed to delete lecture.', { cause: error });
  }
}

/**
 * Permanently deletes a Question Bank (Quiz) and its associated questions atomically.
 */
export async function deleteQuestionBankAdmin(
  admin: { uid: string; email: string },
  bankId: number
) {
  try {
    const { title, qCount } = await db.transaction(async (tx) => {
      const existing = await tx
        .select()
        .from(questionBanks)
        .where(eq(questionBanks.id, bankId));
      const bank = existing[0];
      const bankTitle = bank?.title || `Quiz Bank #${bankId}`;

      const bankQuestions = await tx
        .select({ id: questions.id })
        .from(questions)
        .where(eq(questions.questionBankId, bankId));
      const qIds = bankQuestions.map((q) => q.id);

      if (qIds.length > 0) {
        await tx.delete(bookmarks).where(inArray(bookmarks.questionId, qIds));
        await tx
          .delete(questionAttempts)
          .where(inArray(questionAttempts.questionId, qIds));
        await tx.delete(questions).where(inArray(questions.id, qIds));
      }

      await tx.delete(questionBanks).where(eq(questionBanks.id, bankId));
      return { title: bankTitle, qCount: qIds.length };
    });

    await logAdminAction(
      admin.uid,
      admin.email,
      'DELETE_QUIZ_BANK',
      'question_bank',
      bankId,
      `Permanently deleted quiz bank "${title}" and ${qCount} question(s).`
    );

    return {
      action: 'deleted',
      message: `Quiz "${title}" and its questions were permanently deleted.`,
    };
  } catch (error) {
    console.error('Error deleting quiz bank:', error);
    throw new Error('Failed to delete quiz bank.', { cause: error });
  }
}

/**
 * Permanently deletes a Question and any bookmarks/attempts referencing it atomically.
 */
export async function deleteOrArchiveQuestionAdmin(
  admin: { uid: string; email: string },
  questionId: number
) {
  try {
    await db.transaction(async (tx) => {
      await tx.delete(bookmarks).where(eq(bookmarks.questionId, questionId));
      await tx
        .delete(questionAttempts)
        .where(eq(questionAttempts.questionId, questionId));
      await tx.delete(questions).where(eq(questions.id, questionId));
    });

    await logAdminAction(
      admin.uid,
      admin.email,
      'DELETE_QUESTION',
      'question',
      questionId,
      `Permanently deleted question #${questionId}`
    );
    return {
      action: 'deleted',
      message: `Question #${questionId} was permanently deleted.`,
    };
  } catch (error) {
    console.error('Error deleting question:', error);
    throw new Error('Failed to delete question.', { cause: error });
  }
}

/**
 * Permanently deletes a Student Exam / Quiz Session and its attempts atomically.
 */
export async function deleteExamSessionAdmin(
  admin: { uid: string; email: string },
  sessionId: number
) {
  try {
    await db.transaction(async (tx) => {
      await tx
        .delete(questionAttempts)
        .where(eq(questionAttempts.sessionId, sessionId));
      await tx.delete(examSessions).where(eq(examSessions.id, sessionId));
    });

    await logAdminAction(
      admin.uid,
      admin.email,
      'DELETE_EXAM_SESSION',
      'exam_session',
      sessionId,
      `Permanently deleted student quiz session #${sessionId}`
    );

    return {
      action: 'deleted',
      message: `Quiz session #${sessionId} was permanently deleted.`,
    };
  } catch (error) {
    console.error('Error deleting exam session:', error);
    throw new Error('Failed to delete quiz session.', { cause: error });
  }
}

/**
 * Changes a user's role between 'student' and 'admin' (one user at a time).
 * The primary owner account (zeyadzedan098@gmail.com) is protected and cannot be demoted.
 */
export async function updateUserRoleAdmin(
  admin: { uid: string; email: string },
  targetUid: string,
  newRole: 'student' | 'admin'
) {
  try {
    const existing = await db
      .select()
      .from(users)
      .where(eq(users.uid, targetUid));
    const targetUser = existing[0];
    if (!targetUser) {
      throw new ClientSafeError('User account not found.', 404);
    }

    if (isOwnerAdminEmail(targetUser.email) && newRole !== 'admin') {
      throw new ClientSafeError(
        'The primary owner administrator account cannot be changed to student.',
        403
      );
    }

    const [updated] = await db
      .update(users)
      .set({
        role: newRole,
        updatedAt: new Date(),
      })
      .where(eq(users.uid, targetUid))
      .returning();

    await logAdminAction(
      admin.uid,
      admin.email,
      'UPDATE_USER_ROLE',
      'user',
      targetUser.email,
      `Changed role of "${targetUser.displayName}" (${targetUser.email}) to ${newRole.toUpperCase()}`
    );

    return {
      user: sanitizeUserForClient(updated),
      message: `${targetUser.displayName} (${targetUser.email}) is now set to ${
        newRole === 'admin' ? 'Administrator' : 'Student'
      }.`,
    };
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error updating user role:', error);
    throw new Error('Failed to update user role.', { cause: error });
  }
}

/**
 * Deletes a single user account and their individual records atomically, recording a tombstone
 * so any active tokens for the deleted user are immediately rejected.
 * The primary owner account (zeyadzedan098@gmail.com) cannot be deleted.
 */
export async function deleteUserAdmin(
  admin: { uid: string; email: string },
  targetUid: string
) {
  try {
    const existing = await db
      .select()
      .from(users)
      .where(eq(users.uid, targetUid));
    const targetUser = existing[0];
    if (!targetUser) {
      throw new ClientSafeError('User account not found.', 404);
    }

    if (isOwnerAdminEmail(targetUser.email)) {
      throw new ClientSafeError(
        'The primary owner administrator account cannot be deleted.',
        403
      );
    }

    await deleteUserAccount(targetUid);

    await logAdminAction(
      admin.uid,
      admin.email,
      'DELETE_USER',
      'user',
      targetUser.email,
      `Permanently deleted user account "${targetUser.displayName}" (${targetUser.email})`
    );

    return {
      action: 'deleted',
      message: `User account "${targetUser.displayName}" (${targetUser.email}) was permanently deleted.`,
    };
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error deleting user:', error);
    throw new Error('Failed to delete user account.', { cause: error });
  }
}

/**
 * Bulk CSV Question Validation & Transactional Import
 */
export async function previewCsvImportAdmin(csvContent: string) {
  try {
    await ensureSeededDatabase();
    const existingQuestions = await db.select().from(questions);
    const existingHashes = new Set(
      existingQuestions.map((q) => q.contentHash).filter(Boolean)
    );

    const report = parseAndValidateCsvQuestions(csvContent, existingHashes);
    const pastBatches = await db
      .select()
      .from(importBatches)
      .where(eq(importBatches.fileHash, report.fileHash));

    return {
      ...report,
      alreadyImportedBatch: pastBatches[0] || null,
    };
  } catch (error) {
    console.error('Error previewing CSV import:', error);
    throw new Error('Failed to validate CSV file.', { cause: error });
  }
}

export async function executeCsvImportAdmin(
  admin: { uid: string; email: string },
  fileName: string,
  csvContent: string
) {
  try {
    await ensureSeededDatabase();
    const existingQuestions = await db.select().from(questions);
    const existingHashes = new Set(
      existingQuestions.map((q) => q.contentHash).filter(Boolean)
    );

    const report = parseAndValidateCsvQuestions(csvContent, existingHashes);
    if (report.headerErrors.length > 0) {
      throw new ClientSafeError(report.headerErrors.join(' '), 400);
    }

    const existingBatch = await db
      .select()
      .from(importBatches)
      .where(eq(importBatches.fileHash, report.fileHash));

    if (existingBatch.length > 0 && report.validCount === 0) {
      throw new ClientSafeError(
        `Duplicate file submission prevented: "${fileName}" was already imported on ${new Date(
          existingBatch[0].createdAt
        ).toLocaleString()}.`,
        409
      );
    }

    const validRows = report.rows.filter((r) => r.isValid);
    const skippedCount = report.duplicateCount;
    const failedCount = report.invalidCount;

    const batchRecord = await db.transaction(async (tx) => {
      const allSubjects = await tx.select().from(subjects);
      const allLectures = await tx.select().from(lectures);

      const subjectByTitle = new Map(
        allSubjects.map((s) => [s.title.toLowerCase().trim(), s])
      );
      const lectureByKey = new Map(
        allLectures.map((l) => [`${l.subjectId}:${l.title.toLowerCase().trim()}`, l])
      );

      let importedCount = 0;

      for (const row of validRows) {
        const subjKey = row.subject.toLowerCase().trim();
        let subj = subjectByTitle.get(subjKey);
        if (!subj) {
          const slug = `${subjKey.replace(/[^a-z0-9]+/g, '-')}-${Date.now().toString(36)}-${importedCount}`;
          const [newSubj] = await tx
            .insert(subjects)
            .values({
              slug,
              title: row.subject.trim(),
              description: `Imported subject: ${row.subject.trim()}`,
              displayOrder: subjectByTitle.size + 1,
              status: 'published',
            })
            .returning();
          subj = newSubj;
          subjectByTitle.set(subjKey, subj);
        }

        const lectKey = `${subj.id}:${row.lecture.toLowerCase().trim()}`;
        let lect = lectureByKey.get(lectKey);
        if (!lect) {
          const [newLect] = await tx
            .insert(lectures)
            .values({
              subjectId: subj.id,
              title: row.lecture.trim(),
              description: `Imported lecture for ${subj.title}`,
              lectureNumber: 1,
              status: 'published',
            })
            .returning();
          lect = newLect;
          lectureByKey.set(lectKey, lect);
        }

        await tx.insert(questions).values({
          subjectId: subj.id,
          lectureId: lect.id,
          questionText: row.questionText,
          optionA: row.optionA,
          optionB: row.optionB,
          optionC: row.optionC,
          optionD: row.optionD,
          correctAnswer: row.correctAnswer,
          explanation: row.explanation,
          explanationA: row.explanationA,
          explanationB: row.explanationB,
          explanationC: row.explanationC,
          explanationD: row.explanationD,
          difficulty: row.difficulty,
          tags: row.tags,
          status: row.status,
          version: 1,
          contentHash: row.contentHash,
        });

        importedCount++;
      }

      const [insertedBatch] = await tx
        .insert(importBatches)
        .values({
          adminUid: admin.uid,
          fileName: fileName || 'questions_import.csv',
          fileHash: report.fileHash,
          totalRows: report.totalRows,
          importedCount,
          skippedCount,
          failedCount,
          summaryJson: JSON.stringify({
            importedCount,
            skippedCount,
            failedCount,
          }),
        })
        .returning();

      return insertedBatch;
    });

    await logAdminAction(
      admin.uid,
      admin.email,
      'BULK_CSV_IMPORT',
      'import_batch',
      batchRecord.id,
      `Imported ${batchRecord.importedCount} questions from "${fileName}" (${skippedCount} duplicates skipped, ${failedCount} invalid rows rejected)`
    );

    return {
      batch: batchRecord,
      report,
    };
  } catch (error: any) {
    if (error instanceof ClientSafeError) throw error;
    console.error('Error executing CSV import:', error);
    throw new Error('Failed to complete bulk CSV import.', { cause: error });
  }
}

export async function exportQuestionBankCsvAdmin(): Promise<string> {
  try {
    const allSubjects = await db.select().from(subjects);
    const allLectures = await db.select().from(lectures);
    const allQuestions = await db
      .select()
      .from(questions)
      .orderBy(asc(questions.subjectId), asc(questions.lectureId), asc(questions.id));

    const sMap = new Map(allSubjects.map((s) => [s.id, s.title]));
    const lMap = new Map(allLectures.map((l) => [l.id, l.title]));

    const escapeCsv = (val: string) => `"${(val || '').replace(/"/g, '""')}"`;

    const headers = [
      'subject',
      'lecture',
      'question_text',
      'option_a',
      'option_b',
      'option_c',
      'option_d',
      'correct_answer',
      'explanation',
      'explanation_a',
      'explanation_b',
      'explanation_c',
      'explanation_d',
      'difficulty',
      'tags',
      'status',
    ].join(',');

    const lines = allQuestions.map((q) =>
      [
        escapeCsv(sMap.get(q.subjectId) || ''),
        escapeCsv(lMap.get(q.lectureId) || ''),
        escapeCsv(q.questionText),
        escapeCsv(q.optionA),
        escapeCsv(q.optionB),
        escapeCsv(q.optionC),
        escapeCsv(q.optionD),
        escapeCsv(q.correctAnswer),
        escapeCsv(q.explanation),
        escapeCsv(q.explanationA),
        escapeCsv(q.explanationB),
        escapeCsv(q.explanationC),
        escapeCsv(q.explanationD),
        escapeCsv(q.difficulty),
        escapeCsv(q.tags),
        escapeCsv(q.status),
      ].join(',')
    );

    return [headers, ...lines].join('\n');
  } catch (error) {
    console.error('Error exporting question bank CSV:', error);
    throw new Error('Failed to export question bank CSV.', { cause: error });
  }
}
