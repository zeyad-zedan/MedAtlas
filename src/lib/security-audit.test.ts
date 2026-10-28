import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { eq, inArray } from 'drizzle-orm';

process.env.NODE_ENV = 'test';

import {
  validateSessionSecret,
  createServerSessionToken,
  verifyServerSessionToken,
  verifyPassword,
  verifyPasswordAsync,
  hashPasswordAsync,
  validatePasswordBounds,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_PASSWORD_BYTES,
  hashRecoveryToken,
  requireAuth,
  recordUserSessionRevocation,
  setFirebaseTokenVerifierForTests,
  setFirebaseLookupRestHandlerForTests,
  type AuthRequest,
} from '../middleware/auth.ts';
import {
  createBoundedRateLimiter,
  createPostgresRateLimitStore,
  resolveRateLimitStoreConfig,
  normalizeClientIp,
  resolveTrustProxyConfig,
} from '../middleware/rate-limit.ts';
import { sanitizeSvgDiagram } from './mcq-engine.ts';
import {
  OWNER_ADMIN_EMAIL,
  ClientSafeError,
  evaluateServerExamDeadline,
  registerEmailPasswordUser,
  findUserByEmail,
  getAuthenticatedUserByUid,
  getOrCreateUser,
  validateTrustedRecoveryOrigin,
  extractRecoveryCodeFromInput,
  resolveUserFirebaseUid,
  setFirebaseOobHandlerForTests,
  setFirebasePasswordUpdateHandlerForTests,
  setFirebasePasswordVerifyHandlerForTests,
  setFirebaseProvisioningHandlerForTests,
  setFirebaseEmailDispatchHandlerForTests,
  setFirebaseAccountDeletionHandlerForTests,
  setSimulateDbFailureAfterProviderSyncForTests,
  requestPasswordRecoveryToken,
  confirmPasswordRecoveryToken,
  authenticateEmailUser,
  changeAuthenticatedUserPassword,
  linkPasswordToAuthenticatedAccount,
  updateUserProfile,
  revokeUserSessions,
  deleteUserAccount,
  reconcilePendingDeletedAccounts,
  updateUserRoleAdmin,
  toggleBookmarkForStudent,
  saveSessionQuestionAnswer,
  completeExamSession,
  type LocalEmailTransportFn,
} from '../db/repository.ts';
import { db, pool, isDatabaseConfigured } from '../db/index.ts';
import {
  users,
  passwordResetTokens,
  deletedAccounts,
  rateLimitBuckets,
  subjects,
  lectures,
  questions,
  bookmarks,
  examSessions,
  questionAttempts,
} from '../db/schema.ts';

const TEST_RUN_ID = Date.now().toString(36);
const createdUserUids: string[] = [];
const createdSubjectIds: number[] = [];
const createdLectureIds: number[] = [];
const createdQuestionIds: number[] = [];
const createdSessionIds: number[] = [];

after(async () => {
  setFirebaseTokenVerifierForTests(null);
  setFirebaseLookupRestHandlerForTests(null);
  setFirebaseOobHandlerForTests(null);
  setFirebasePasswordUpdateHandlerForTests(null);
  setFirebasePasswordVerifyHandlerForTests(null);
  setFirebaseProvisioningHandlerForTests(null);
  setFirebaseEmailDispatchHandlerForTests(null);
  setFirebaseAccountDeletionHandlerForTests(null);
  try {
    if (createdSessionIds.length > 0) {
      await db
        .delete(questionAttempts)
        .where(inArray(questionAttempts.sessionId, createdSessionIds));
      await db
        .delete(examSessions)
        .where(inArray(examSessions.id, createdSessionIds));
    }
    if (createdQuestionIds.length > 0) {
      await db
        .delete(bookmarks)
        .where(inArray(bookmarks.questionId, createdQuestionIds));
      await db.delete(questions).where(inArray(questions.id, createdQuestionIds));
    }
    if (createdLectureIds.length > 0) {
      await db.delete(lectures).where(inArray(lectures.id, createdLectureIds));
    }
    if (createdSubjectIds.length > 0) {
      await db.delete(subjects).where(inArray(subjects.id, createdSubjectIds));
    }
    if (createdUserUids.length > 0) {
      await db
        .delete(bookmarks)
        .where(inArray(bookmarks.userUid, createdUserUids));
      await db
        .delete(passwordResetTokens)
        .where(inArray(passwordResetTokens.userUid, createdUserUids));
      await db
        .delete(deletedAccounts)
        .where(inArray(deletedAccounts.uid, createdUserUids));
      await db.delete(users).where(inArray(users.uid, createdUserUids));
    }
  } catch (cleanupErr) {
    console.error('Test cleanup warning:', cleanupErr);
  } finally {
    await pool.end();
  }
});

describe('Security & Reliability Audit Regression Suite', () => {
  // ==========================================================================
  // PRIORITY 1: ELIMINATE UNAUTHORIZED ADMINISTRATOR PROVISIONING
  // ==========================================================================
  it('P1. Prevents local registration with OWNER_ADMIN_EMAIL from granting admin, blocks unverified admin promotion, enforces admin RBAC, and serializes concurrent bootstrap', async () => {
    // Snapshot any existing owner row so we can test clean bootstrap & restore afterward
    const existingOwnerRows = await db
      .select()
      .from(users)
      .where(eq(users.email, OWNER_ADMIN_EMAIL));
    const savedOwner = existingOwnerRows[0] || null;

    try {
      if (savedOwner) {
        await db.delete(users).where(eq(users.uid, savedOwner.uid));
      }

      // 1. Local registration using OWNER_ADMIN_EMAIL must NEVER grant admin or emailVerified
      const localOwnerAttempt = await registerEmailPasswordUser(
        OWNER_ADMIN_EMAIL,
        'AttackerLocalPass123!',
        'Unverified Local Registrant'
      );
      assert.equal(
        localOwnerAttempt.role,
        'student',
        'Local registration with OWNER_ADMIN_EMAIL must never grant admin role'
      );
      assert.equal(
        localOwnerAttempt.emailVerified,
        false,
        'Local registration must not mark emailVerified = true without verification'
      );

      // 2. Subsequent reads via getAuthenticatedUserByUid and findUserByEmail must NOT auto-promote to admin
      const fetchedByUid = await getAuthenticatedUserByUid(localOwnerAttempt.uid);
      assert.equal(fetchedByUid?.role, 'student');
      const fetchedByEmail = await findUserByEmail(OWNER_ADMIN_EMAIL);
      assert.equal(fetchedByEmail?.role, 'student');

      // Clean up the unverified local account before testing verified Firebase bootstrap
      await db.delete(users).where(eq(users.uid, localOwnerAttempt.uid));

      // 3. Unverified Firebase user with OWNER_ADMIN_EMAIL must be rejected (403)
      await assert.rejects(
        async () => {
          await getOrCreateUser(
            `fb_unverified_owner_${TEST_RUN_ID}`,
            OWNER_ADMIN_EMAIL,
            'Unverified Firebase Owner',
            { authType: 'firebase', emailVerified: false, allowCreate: true }
          );
        },
        (err: any) => err instanceof ClientSafeError && err.statusCode === 403
      );

      // 4. Concurrent first-admin provisioning via verified Firebase identity must be race-safe
      const verifiedOwnerUid = savedOwner?.uid || `fb_verified_owner_${TEST_RUN_ID}`;
      const [boot1, boot2, boot3] = await Promise.all([
        getOrCreateUser(verifiedOwnerUid, OWNER_ADMIN_EMAIL, 'Verified Owner Admin', {
          authType: 'firebase',
          emailVerified: true,
          allowCreate: true,
        }),
        getOrCreateUser(verifiedOwnerUid, OWNER_ADMIN_EMAIL, 'Verified Owner Admin', {
          authType: 'firebase',
          emailVerified: true,
          allowCreate: true,
        }),
        getOrCreateUser(verifiedOwnerUid, OWNER_ADMIN_EMAIL, 'Verified Owner Admin', {
          authType: 'firebase',
          emailVerified: true,
          allowCreate: true,
        }),
      ]);

      assert.equal(boot1.role, 'admin');
      assert.equal(boot2.role, 'admin');
      assert.equal(boot3.role, 'admin');
      assert.equal(boot1.emailVerified, true);

      // A concurrent second UID attempting to claim OWNER_ADMIN_EMAIL must be rejected with 409
      await assert.rejects(
        async () => {
          await getOrCreateUser(
            `fb_competing_owner_${TEST_RUN_ID}`,
            OWNER_ADMIN_EMAIL,
            'Competing Owner',
            { authType: 'firebase', emailVerified: true, allowCreate: true }
          );
        },
        (err: any) => err instanceof ClientSafeError && err.statusCode === 409
      );

      // 5. Silent email reassignment on an existing admin UID must be rejected with 409
      await assert.rejects(
        async () => {
          await getOrCreateUser(
            verifiedOwnerUid,
            `reassigned.${TEST_RUN_ID}@medatlas.test`,
            'Reassigned Email Attempt',
            { authType: 'firebase', emailVerified: true, allowCreate: true }
          );
        },
        (err: any) => err instanceof ClientSafeError && err.statusCode === 409
      );

      // 6. Normal students cannot change their own role or another user's role
      const normalStudent = await registerEmailPasswordUser(
        `student.rbac.${TEST_RUN_ID}@medatlas.test`,
        'StudentRbacPass123!',
        'Normal Student'
      );
      createdUserUids.push(normalStudent.uid);

      await assert.rejects(
        async () => {
          await updateUserRoleAdmin(
            { uid: normalStudent.uid, email: normalStudent.email },
            normalStudent.uid,
            'admin'
          );
        },
        (err: any) => err instanceof ClientSafeError && err.statusCode === 403
      );

      // 7. Legitimate verified administrator can promote and demote a student account
      const promoted = await updateUserRoleAdmin(
        { uid: boot1.uid, email: boot1.email },
        normalStudent.uid,
        'admin'
      );
      assert.equal(promoted.user.role, 'admin');

      const demoted = await updateUserRoleAdmin(
        { uid: boot1.uid, email: boot1.email },
        normalStudent.uid,
        'student'
      );
      assert.equal(demoted.user.role, 'student');

      // Verified owner admin cannot be demoted to student
      await assert.rejects(
        async () => {
          await updateUserRoleAdmin(
            { uid: boot1.uid, email: boot1.email },
            boot1.uid,
            'student'
          );
        },
        (err: any) => err instanceof ClientSafeError && err.statusCode === 403
      );

      if (!savedOwner) {
        await db.delete(users).where(eq(users.uid, verifiedOwnerUid));
      }
    } finally {
      if (savedOwner) {
        const current = await db
          .select()
          .from(users)
          .where(eq(users.uid, savedOwner.uid));
        if (current.length === 0) {
          await db.insert(users).values(savedOwner);
        }
      }
    }
  });

  // ==========================================================================
  // PRIORITY 2: REPAIR THE BROKEN HYBRID PASSWORD-RESET ARCHITECTURE
  // ==========================================================================
  it('P2.1 Rejects unauthenticated password reset attempts that lack a valid recovery token', async () => {
    await assert.rejects(
      async () => {
        await confirmPasswordRecoveryToken('', 'NewCompromisedPass123!');
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 400 &&
        /recovery token/i.test(err.message)
    );

    await assert.rejects(
      async () => {
        await confirmPasswordRecoveryToken('short-invalid-token', 'NewCompromisedPass123!');
      },
      (err: any) => err instanceof ClientSafeError && err.statusCode === 400
    );
  });

  it('P2.2 Password reset uses Firebase Auth without webhooks, delivers generic enumeration protection, and verifies trusted origins', async () => {
    const email = `sec.reset.${TEST_RUN_ID}@medatlas.test`;
    const user = await registerEmailPasswordUser(
      email,
      'InitialSecurePass123!',
      'Reset Test Student'
    );
    createdUserUids.push(user.uid);

    // 1. Verify exact allowlisted recovery origins are trusted while arbitrary *.ai.studio / *.run.app are rejected
    assert.equal(
      validateTrustedRecoveryOrigin('https://medatlas.ai.studio'),
      'https://medatlas.ai.studio'
    );
    assert.equal(
      validateTrustedRecoveryOrigin(
        'https://ais-dev-5mhsafvm6orewiuxge6ast-323922691346.europe-west1.run.app'
      ),
      'https://ais-dev-5mhsafvm6orewiuxge6ast-323922691346.europe-west1.run.app'
    );

    // Arbitrary *.ai.studio or external origins must be rejected unless explicitly in ALLOWED_RECOVERY_ORIGINS
    await assert.rejects(
      async () => {
        validateTrustedRecoveryOrigin('https://preview-test.ai.studio');
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 400 &&
        /untrusted/i.test(err.message)
    );
    await assert.rejects(
      async () => {
        validateTrustedRecoveryOrigin('https://evil-phishing.example.com');
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 400 &&
        /untrusted/i.test(err.message)
    );

    // 2. Requesting reset does NOT require LOCAL_PASSWORD_RESET_WEBHOOK_URL and succeeds via Firebase Auth
    delete process.env.LOCAL_PASSWORD_RESET_WEBHOOK_URL;
    delete process.env.PASSWORD_RESET_WEBHOOK_URL;

    const fbResetRes = await requestPasswordRecoveryToken(email, {
      origin: 'https://medatlas.ai.studio',
      triggerFirebaseEmail: false, // Don't make real outbound network call in unit test
    });
    assert.equal(fbResetRes.accepted, true);
    assert.equal(fbResetRes.deliveryChannel, 'firebase');
    assert.ok(fbResetRes.message.length > 10);

    // 3. Non-existent email receives the exact same generic confirmation (no enumeration)
    const nonExistentRes = await requestPasswordRecoveryToken(
      `unknown.${TEST_RUN_ID}@medatlas.test`,
      { origin: 'https://medatlas.ai.studio' }
    );
    assert.equal(nonExistentRes.accepted, true);
    assert.equal(nonExistentRes.message, fbResetRes.message);
    assert.equal(nonExistentRes.deliveryChannel, 'noop');

    // 3. Configure local reset email transport and verify end-to-end local recovery flow
    const dispatchedEmails: Array<{
      to: string;
      displayName: string;
      resetUrl: string;
      expiresInMinutes: number;
    }> = [];
    const localTransport: LocalEmailTransportFn = async (payload) => {
      dispatchedEmails.push(payload);
    };

    const oldSessionToken = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
      tokenVersion: user.tokenVersion,
    });

    // Request token #1, then immediately request token #2 (which must supersede token #1)
    const req1 = await requestPasswordRecoveryToken(email, {
      returnTokenForTesting: true,
      localEmailTransport: localTransport,
    });
    const req2 = await requestPasswordRecoveryToken(email, {
      returnTokenForTesting: true,
      localEmailTransport: localTransport,
    });

    assert.equal(req1.deliveryChannel, 'local_token');
    assert.equal(req2.deliveryChannel, 'local_token');
    assert.equal(dispatchedEmails.length, 2);
    assert.ok(dispatchedEmails[1].resetUrl.includes(req2._testRecoveryToken!));

    // Verify raw token is NEVER stored in the database (only SHA-256 hash)
    const dbTokens = await db
      .select()
      .from(passwordResetTokens)
      .where(eq(passwordResetTokens.userUid, user.uid));
    for (const row of dbTokens) {
      assert.notEqual(row.tokenHash, req1._testRecoveryToken);
      assert.notEqual(row.tokenHash, req2._testRecoveryToken);
    }
    const matchingHashed = dbTokens.find(
      (r) => r.tokenHash === hashRecoveryToken(req2._testRecoveryToken!)
    );
    assert.ok(matchingHashed, 'Database must store SHA-256 hash of recovery token');

    // Superseded token #1 must be rejected
    await assert.rejects(
      async () => {
        await confirmPasswordRecoveryToken(
          req1._testRecoveryToken!,
          'AttemptWithSupersededToken123!'
        );
      },
      (err: any) => err instanceof ClientSafeError && err.statusCode === 400
    );

    // Valid token #2 succeeds once and increments tokenVersion
    const updatedUser = await confirmPasswordRecoveryToken(
      req2._testRecoveryToken!,
      'UpdatedValidPass456!'
    );
    assert.equal(updatedUser.tokenVersion, 2);

    // Reusing token #2 a second time must be rejected (single-use enforcement)
    await assert.rejects(
      async () => {
        await confirmPasswordRecoveryToken(
          req2._testRecoveryToken!,
          'ReplayAttackPass789!'
        );
      },
      (err: any) => err instanceof ClientSafeError && err.statusCode === 400
    );

    // Expired token must be rejected
    const expiredRaw = crypto.randomBytes(32).toString('hex');
    await db.insert(passwordResetTokens).values({
      userUid: user.uid,
      tokenHash: hashRecoveryToken(expiredRaw),
      expiresAt: new Date(Date.now() - 60_000),
    });

    await assert.rejects(
      async () => {
        await confirmPasswordRecoveryToken(expiredRaw, 'ExpiredTokenPass999!');
      },
      (err: any) => err instanceof ClientSafeError && err.statusCode === 400
    );

    // Prior session token (tokenVersion=1) must now be rejected by requireAuth (401)
    let statusCaptured = 200;
    const mockReq = {
      headers: { authorization: `Bearer ${oldSessionToken}` },
    } as unknown as AuthRequest;
    const mockRes = {
      status(code: number) {
        statusCaptured = code;
        return this;
      },
      json(_body: any) {
        return this;
      },
    } as any;
    let nextCalled = false;
    await requireAuth(mockReq, mockRes, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, false);
    assert.equal(statusCaptured, 401);

    // Old password must no longer authenticate; new password must authenticate
    const userInDbAfterReset = await findUserByEmail(email);
    assert.ok(userInDbAfterReset?.passwordHash);
    assert.equal(
      verifyPassword('InitialSecurePass123!', userInDbAfterReset.passwordHash),
      false
    );
    assert.equal(
      verifyPassword('UpdatedValidPass456!', userInDbAfterReset.passwordHash),
      true
    );
  });

  it('P2.3 Firebase-only password reset creates zero unused DB tokens, and linked-account Firebase oobCode reset invalidates the old local password', async () => {
    const fbUid = `fb_reset_only_${TEST_RUN_ID}`;
    const fbEmail = `fb.reset.only.${TEST_RUN_ID}@medatlas.test`;
    createdUserUids.push(fbUid);

    await getOrCreateUser(fbUid, fbEmail, 'Firebase Reset User', {
      authType: 'firebase',
      emailVerified: true,
      allowCreate: true,
    });

    // Request password reset for a Firebase-only account
    const fbResetRes = await requestPasswordRecoveryToken(fbEmail);
    assert.equal(fbResetRes.accepted, true);
    assert.equal(fbResetRes.deliveryChannel, 'firebase');

    // Verify ZERO unused rows were created in password_reset_tokens for the Firebase-only account
    const fbDbTokens = await db
      .select()
      .from(passwordResetTokens)
      .where(eq(passwordResetTokens.userUid, fbUid));
    assert.equal(
      fbDbTokens.length,
      0,
      'Firebase-backed password reset must not insert unused tokens into password_reset_tokens'
    );

    // Link a local password to make this a hybrid ('both') account
    const linked = await linkPasswordToAuthenticatedAccount(
      fbUid,
      'OldLinkedPassword123!'
    );
    assert.equal(linked.authProvider, 'both');

    // Simulate completing a Firebase oobCode reset via the 2-phase handler and verify old local password is invalidated
    let phase1Verified = false;
    let phase2Consumed = false;
    setFirebaseOobHandlerForTests({
      verifyOnly: async (code) => {
        assert.equal(code, 'firebase_oob_code_valid_test_token_12345');
        phase1Verified = true;
        return { email: fbEmail };
      },
      consume: async (code, _newPass) => {
        assert.equal(code, 'firebase_oob_code_valid_test_token_12345');
        assert.equal(phase1Verified, true, 'Phase 1 verifyOnly must run before Phase 2 consume');
        phase2Consumed = true;
        return { email: fbEmail };
      },
    });

    try {
      await confirmPasswordRecoveryToken(
        'firebase_oob_code_valid_test_token_12345',
        'NewFirebaseSyncedPass789!'
      );
      assert.equal(phase2Consumed, true);
    } finally {
      setFirebaseOobHandlerForTests(null);
    }

    const afterHybridReset = await findUserByEmail(fbEmail);
    assert.ok(afterHybridReset?.passwordHash);
    assert.equal(
      verifyPassword('OldLinkedPassword123!', afterHybridReset.passwordHash),
      false,
      'Old local password on a linked account must be invalidated after Firebase oobCode password reset'
    );
    assert.equal(
      verifyPassword('NewFirebaseSyncedPass789!', afterHybridReset.passwordHash),
      true
    );
  });

  it('P2.4 Untrusted recovery origins (including arbitrary *.ai.studio / *.run.app) are rejected, while exact allowlisted origins succeed', async () => {
    // Exact allowlisted origins must succeed
    assert.equal(
      validateTrustedRecoveryOrigin('https://medatlas.ai.studio'),
      'https://medatlas.ai.studio'
    );
    assert.equal(
      validateTrustedRecoveryOrigin(
        'https://ais-pre-5mhsafvm6orewiuxge6ast-323922691346.europe-west1.run.app'
      ),
      'https://ais-pre-5mhsafvm6orewiuxge6ast-323922691346.europe-west1.run.app'
    );

    // Arbitrary subdomain of .ai.studio or .run.app must be rejected unless explicitly configured
    await assert.rejects(
      async () => validateTrustedRecoveryOrigin('https://preview-test.ai.studio'),
      (err: any) => err instanceof ClientSafeError && err.statusCode === 400
    );
    await assert.rejects(
      async () => validateTrustedRecoveryOrigin('https://other-tenant-xyz.run.app'),
      (err: any) => err instanceof ClientSafeError && err.statusCode === 400
    );

    // Path or query injection in recovery origin must be rejected with 400
    await assert.rejects(
      async () => validateTrustedRecoveryOrigin('https://medatlas.ai.studio/path-injection'),
      (err: any) => err instanceof ClientSafeError && err.statusCode === 400
    );

    // Untrusted external origin must be rejected with 400
    await assert.rejects(
      async () => validateTrustedRecoveryOrigin('https://attacker-phishing.example.com'),
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 400 &&
        /untrusted/i.test(err.message)
    );

    // End-to-end forgot-password request with origin https://medatlas.ai.studio succeeds
    const testEmail = `origin.test.${TEST_RUN_ID}@medatlas.test`;
    const localUser = await registerEmailPasswordUser(
      testEmail,
      'OriginSecurePass123!',
      'Origin Student'
    );
    createdUserUids.push(localUser.uid);

    const resetRes = await requestPasswordRecoveryToken(testEmail, {
      origin: 'https://medatlas.ai.studio',
      triggerFirebaseEmail: false,
    });
    assert.equal(resetRes.accepted, true);
    assert.equal(resetRes.deliveryChannel, 'firebase');

    // Authenticate email user with local password succeeds
    const authed = await authenticateEmailUser(testEmail, 'OriginSecurePass123!');
    assert.ok(authed);
    assert.equal(authed.email, testEmail);

    // Incorrect password fails
    const badAuth = await authenticateEmailUser(testEmail, 'WrongPassword123!');
    assert.equal(badAuth, null);
  });

  it('P2.5 Firebase provisioning failure and email delivery failure are handled safely without exposing account existence', async () => {
    const testEmail = `error.handling.${TEST_RUN_ID}@medatlas.test`;
    const user = await registerEmailPasswordUser(
      testEmail,
      'ErrorHandlingPass123!',
      'Error Handling Student'
    );
    createdUserUids.push(user.uid);

    // 1. Firebase user provisioning failure:
    // When ensureUserExistsInFirebaseAuth fails (returns false), requestPasswordRecoveryToken
    // detects the failure, logs it safely, returns accepted: true with generic message, and does NOT leak existence.
    setFirebaseProvisioningHandlerForTests(async () => false);
    try {
      const provFailRes = await requestPasswordRecoveryToken(testEmail, {
        origin: 'https://medatlas.ai.studio',
        triggerFirebaseEmail: true,
      });
      assert.equal(provFailRes.accepted, true);
      assert.ok(provFailRes.message.length > 10);
      assert.equal(provFailRes.deliveryChannel, 'firebase_provisioning_failure');

      // Compare with non-existent user response: identical client-visible contract
      const nonExistentRes = await requestPasswordRecoveryToken(
        `nonexistent.${TEST_RUN_ID}@medatlas.test`,
        { origin: 'https://medatlas.ai.studio' }
      );
      assert.equal(nonExistentRes.accepted, true);
      assert.equal(nonExistentRes.message, provFailRes.message);
      assert.equal(nonExistentRes.expiresInMinutes, provFailRes.expiresInMinutes);
    } finally {
      setFirebaseProvisioningHandlerForTests(null);
    }

    // 2. Firebase email-delivery failure:
    // When dispatchFirebasePasswordResetEmail fails (returns false), requestPasswordRecoveryToken
    // detects the failure, logs it safely, returns accepted: true with generic message, and does NOT leak existence.
    setFirebaseEmailDispatchHandlerForTests(async () => false);
    try {
      const sendFailRes = await requestPasswordRecoveryToken(testEmail, {
        origin: 'https://medatlas.ai.studio',
        triggerFirebaseEmail: true,
      });
      assert.equal(sendFailRes.accepted, true);
      assert.ok(sendFailRes.message.length > 10);
      assert.equal(sendFailRes.deliveryChannel, 'firebase_send_failure');
    } finally {
      setFirebaseEmailDispatchHandlerForTests(null);
    }
  });

  it('P2.6 Firebase accounts:resetPassword flow validates OOB codes before consuming, rejecting expired, invalid, and used codes without inconsistent state', async () => {
    const testEmail = `oob.validation.${TEST_RUN_ID}@medatlas.test`;
    const initialPassword = 'InitialValidPassword123!';
    const user = await registerEmailPasswordUser(
      testEmail,
      initialPassword,
      'OOB Validation Student'
    );
    createdUserUids.push(user.uid);

    const oldSessionToken = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
      tokenVersion: user.tokenVersion,
    });

    // 1. Expired OOB code: Phase 1 verifyOnly rejects it; consume must NEVER be called; DB state unchanged
    let consumeCalled = false;
    setFirebaseOobHandlerForTests({
      verifyOnly: async () => {
        throw new ClientSafeError(
          'Invalid, expired, or already used password recovery token.',
          400
        );
      },
      consume: async () => {
        consumeCalled = true;
        throw new Error('Consume must not be called when verifyOnly rejects');
      },
    });

    try {
      await assert.rejects(
        async () => {
          await confirmPasswordRecoveryToken(
            'expired_oob_code_test_123456789012345',
            'NewAttemptedPassword123!'
          );
        },
        (err: any) =>
          err instanceof ClientSafeError &&
          err.statusCode === 400 &&
          /Invalid, expired, or already used/i.test(err.message)
      );
      assert.equal(consumeCalled, false);
    } finally {
      setFirebaseOobHandlerForTests(null);
    }

    // Verify DB state was NOT modified: old password and session token still valid
    const userAfterExpired = await findUserByEmail(testEmail);
    assert.equal(userAfterExpired?.tokenVersion, 1);
    assert.equal(verifyPassword(initialPassword, userAfterExpired!.passwordHash!), true);

    // 2. Invalid OOB code: Phase 1 verifyOnly rejects it; consume must NEVER be called
    setFirebaseOobHandlerForTests({
      verifyOnly: async () => {
        throw new ClientSafeError(
          'Invalid, expired, or already used password recovery token.',
          400
        );
      },
      consume: async () => {
        consumeCalled = true;
        throw new Error('Consume must not be called when code is invalid');
      },
    });

    try {
      await assert.rejects(
        async () => {
          await confirmPasswordRecoveryToken(
            'malformed_or_tampered_code_1234567890',
            'NewAttemptedPassword123!'
          );
        },
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );
    } finally {
      setFirebaseOobHandlerForTests(null);
    }

    // 3. Valid OOB code succeeds once, promotes local user to linked 'both', and invalidates prior sessions
    let codeConsumed = false;
    setFirebaseOobHandlerForTests({
      verifyOnly: async (_code) => {
        if (codeConsumed) {
          throw new ClientSafeError(
            'Invalid, expired, or already used password recovery token.',
            400
          );
        }
        return { email: testEmail };
      },
      consume: async (_code, _newPass) => {
        if (codeConsumed) {
          throw new ClientSafeError(
            'Invalid, expired, or already used password recovery token.',
            400
          );
        }
        codeConsumed = true;
        return { email: testEmail };
      },
    });

    const newPassword = 'NewlyUpdatedSecurePassword456!';
    try {
      const resetResult = await confirmPasswordRecoveryToken(
        'valid_single_use_oob_code_1234567890',
        newPassword
      );
      assert.equal(codeConsumed, true);
      assert.equal(resetResult.tokenVersion, 2);
      assert.equal(resetResult.authProvider, 'both');

      // 4. Replay attack: Reusing the same OOB code must be rejected (single-use enforcement)
      await assert.rejects(
        async () => {
          await confirmPasswordRecoveryToken(
            'valid_single_use_oob_code_1234567890',
            'YetAnotherPassword789!'
          );
        },
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );
    } finally {
      setFirebaseOobHandlerForTests(null);
    }

    // 5. Verify credential consistency & session revocation:
    // Old password must NO LONGER authenticate; new password must authenticate
    const finalUser = await findUserByEmail(testEmail);
    assert.equal(verifyPassword(initialPassword, finalUser!.passwordHash!), false);
    assert.equal(verifyPassword(newPassword, finalUser!.passwordHash!), true);
    assert.equal(finalUser?.authProvider, 'both');
    assert.equal(finalUser?.tokenVersion, 2);

    // Old session token (tokenVersion=1) must be rejected with 401
    let sessionStatus = 200;
    const mockReq = {
      headers: { authorization: `Bearer ${oldSessionToken}` },
    } as unknown as AuthRequest;
    const mockRes = {
      status(code: number) {
        sessionStatus = code;
        return this;
      },
      json(_b: any) {
        return this;
      },
    } as any;
    let nextCalled = false;
    await requireAuth(mockReq, mockRes, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, false);
    assert.equal(sessionStatus, 401);
  });

  // ==========================================================================
  // PRIORITY 3: ENFORCE SESSION REVOCATION & ACCOUNT STATUS FOR FIREBASE AUTH
  // ==========================================================================
  it('P3. Enforces session revocation, deleted account tombstones, and suspended account status on Firebase-authenticated requests', async () => {
    const fbUid = `fb_session_guard_${TEST_RUN_ID}`;
    const fbEmail = `fb.session.guard.${TEST_RUN_ID}@medatlas.test`;
    createdUserUids.push(fbUid);

    await getOrCreateUser(fbUid, fbEmail, 'Firebase Guarded User', {
      authType: 'firebase',
      emailVerified: true,
      allowCreate: true,
    });

    const invokeRequireAuth = async (bearerToken: string) => {
      let status = 200;
      let body: any = null;
      let nextCalled = false;
      const req = {
        headers: { authorization: `Bearer ${bearerToken}` },
      } as unknown as AuthRequest;
      const res = {
        status(code: number) {
          status = code;
          return this;
        },
        json(payload: any) {
          body = payload;
          return this;
        },
      } as any;
      await requireAuth(req, res, () => {
        nextCalled = true;
      });
      return { status, body, nextCalled, user: req.user };
    };

    try {
      // 1. Valid verified Firebase token succeeds
      const nowSec = Math.floor(Date.now() / 1000);
      setFirebaseTokenVerifierForTests(async (_token, checkRevoked) => {
        assert.equal(checkRevoked, true, 'verifyIdToken must be called with checkRevoked = true');
        return {
          uid: fbUid,
          email: fbEmail,
          name: 'Firebase Guarded User',
          email_verified: true,
          iat: nowSec,
          auth_time: nowSec,
        };
      });

      const validRes = await invokeRequireAuth('mock.firebase.jwt.token');
      assert.equal(validRes.nextCalled, true);
      assert.equal(validRes.status, 200);

      // 2. Revoking user sessions (logout) invalidates Firebase tokens issued prior to revocation
      await revokeUserSessions(fbUid);
      setFirebaseTokenVerifierForTests(async () => ({
        uid: fbUid,
        email: fbEmail,
        name: 'Firebase Guarded User',
        email_verified: true,
        iat: nowSec - 10, // issued 10s before logout revocation
        auth_time: nowSec - 10,
      }));

      const afterLogoutRes = await invokeRequireAuth('mock.firebase.jwt.token');
      assert.equal(afterLogoutRes.nextCalled, false);
      assert.equal(afterLogoutRes.status, 401);

      // 3. Firebase Admin SDK reporting auth/id-token-revoked returns 401
      setFirebaseTokenVerifierForTests(async () => {
        const err: any = new Error('Firebase ID token has been revoked.');
        err.code = 'auth/id-token-revoked';
        throw err;
      });
      const sdkRevokedRes = await invokeRequireAuth('mock.firebase.jwt.token');
      assert.equal(sdkRevokedRes.nextCalled, false);
      assert.equal(sdkRevokedRes.status, 401);

      // 4. Suspended account status in PostgreSQL blocks Firebase-authenticated requests with 403
      const freshIssuedSec = Math.floor((Date.now() + 5_000) / 1000);
      await db
        .update(users)
        .set({ accountStatus: 'suspended' })
        .where(eq(users.uid, fbUid));

      setFirebaseTokenVerifierForTests(async () => ({
        uid: fbUid,
        email: fbEmail,
        name: 'Firebase Guarded User',
        email_verified: true,
        iat: freshIssuedSec,
        auth_time: freshIssuedSec,
      }));

      const suspendedRes = await invokeRequireAuth('mock.firebase.jwt.token');
      assert.equal(suspendedRes.nextCalled, false);
      assert.equal(suspendedRes.status, 403);

      // Restore active status, then delete account and verify Firebase token is rejected with 401
      await db
        .update(users)
        .set({ accountStatus: 'active' })
        .where(eq(users.uid, fbUid));
      await deleteUserAccount(fbUid);

      const deletedRes = await invokeRequireAuth('mock.firebase.jwt.token');
      assert.equal(deletedRes.nextCalled, false);
      assert.equal(deletedRes.status, 401);
    } finally {
      setFirebaseTokenVerifierForTests(null);
    }
  });

  // ==========================================================================
  // 3, 4 & 5. CRITICAL: SESSION SECRET & TOKEN VERIFICATION
  // ==========================================================================
  it('3 & 4. Rejects missing, short, low-entropy, or placeholder AUTH_SESSION_SECRET values and forged tokens', () => {
    assert.throws(() => validateSessionSecret(undefined), /required/i);
    assert.throws(() => validateSessionSecret(''), /required/i);
    assert.throws(
      () => validateSessionSecret('medatlas_default_server_hmac_secret_2026_secure_key'),
      /placeholder|forbidden/i
    );
    assert.throws(() => validateSessionSecret('short_secret_12345'), /at least 32/i);
    assert.throws(() => validateSessionSecret('a'.repeat(48)), /entropy/i);

    const strongSecret = '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e';
    assert.equal(validateSessionSecret(strongSecret), strongSecret);

    const oldHardcodedSecret = 'medatlas_default_server_hmac_secret_2026_secure_key';
    const forgedPayload = Buffer.from(
      JSON.stringify({
        iss: 'medatlas-local',
        uid: 'usr_admin_forged',
        email: 'zeyadzedan098@gmail.com',
        tokenVersion: 1,
        iat: Date.now(),
        exp: Date.now() + 3600_000,
      })
    ).toString('base64url');

    const forgedLegacySig = crypto
      .createHmac('sha256', oldHardcodedSecret)
      .update(forgedPayload)
      .digest('base64url');
    const forgedLegacyToken = `medatlas.${forgedPayload}.${forgedLegacySig}`;

    const forgedV1Sig = crypto
      .createHmac('sha256', oldHardcodedSecret)
      .update(`medatlas.v1.${forgedPayload}`)
      .digest('base64url');
    const forgedV1Token = `medatlas.v1.${forgedPayload}.${forgedV1Sig}`;

    assert.equal(verifyServerSessionToken(forgedLegacyToken), null);
    assert.equal(verifyServerSessionToken(forgedV1Token), null);

    // Expired token check
    const expiredToken = createServerSessionToken(
      {
        uid: 'usr_expired_test',
        email: 'expired@medatlas.test',
        tokenVersion: 1,
      },
      { nowMs: 1_000_000, ttlMs: 5_000 }
    );
    assert.equal(verifyServerSessionToken(expiredToken, { nowMs: 1_010_000 }), null);
  });

  // ==========================================================================
  // 6 & 7. HIGH: ACCOUNT TAKEOVER PREVENTION IN REGISTRATION & LINKING
  // ==========================================================================
  it('6 & 7. Prevents registration from attaching a password to an existing provider account and blocks unverified linking', async () => {
    const providerUid = `fb_provider_${TEST_RUN_ID}`;
    const providerEmail = `provider.student.${TEST_RUN_ID}@medatlas.test`;
    createdUserUids.push(providerUid);

    const createdProviderUser = await getOrCreateUser(
      providerUid,
      providerEmail,
      'Dr. Provider Student',
      { authType: 'firebase', emailVerified: true, allowCreate: true }
    );
    assert.equal(createdProviderUser.uid, providerUid);
    assert.equal(createdProviderUser.passwordHash, null);

    await assert.rejects(
      async () => {
        await registerEmailPasswordUser(
          providerEmail,
          'AttackerHijackPass123!',
          'Attacker Name'
        );
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 409 &&
        /already exists/i.test(err.message)
    );

    const [victimAfterAttack] = await db
      .select()
      .from(users)
      .where(eq(users.uid, providerUid));
    assert.equal(victimAfterAttack.passwordHash, null);
    assert.equal(victimAfterAttack.displayName, 'Dr. Provider Student');

    await assert.rejects(
      async () => {
        await getOrCreateUser(
          `fb_unverified_${TEST_RUN_ID}`,
          `unverified.${TEST_RUN_ID}@medatlas.test`,
          'Unverified User',
          { authType: 'firebase', emailVerified: false, allowCreate: true }
        );
      },
      (err: any) => err instanceof ClientSafeError && err.statusCode === 403
    );

    await assert.rejects(
      async () => {
        await getOrCreateUser(
          `fb_impersonator_${TEST_RUN_ID}`,
          providerEmail,
          'Impersonator',
          { authType: 'firebase', emailVerified: true, allowCreate: true }
        );
      },
      (err: any) => err instanceof ClientSafeError && err.statusCode === 409
    );

    const linked = await linkPasswordToAuthenticatedAccount(
      providerUid,
      'OwnerLinkedPassword123!'
    );
    assert.ok(linked.passwordHash && linked.passwordHash.length > 0);
    assert.equal(linked.authProvider, 'both');
  });

  // ==========================================================================
  // 8, 9 & P7. SERVER-SIDE EXAM DEADLINES, CONCURRENT COMPLETION & BOOKMARK GUARD
  // ==========================================================================
  it('8, 9 & P7. Enforces server-side exam deadlines, prevents duplicate question_attempts, and blocks bookmarking unpublished questions', async () => {
    const startedMs = 1_700_000_000_000;
    const startedDate = new Date(startedMs);
    const activeDeadline = evaluateServerExamDeadline({
      mode: 'exam',
      startedAt: startedDate,
      timeLimitSeconds: 600,
      nowMs: startedMs + 120_000,
    });
    assert.equal(activeDeadline.isExpired, false);
    assert.equal(activeDeadline.remainingSeconds, 480);

    const expiredDeadline = evaluateServerExamDeadline({
      mode: 'exam',
      startedAt: startedDate,
      timeLimitSeconds: 600,
      nowMs: startedMs + 605_000,
    });
    assert.equal(expiredDeadline.isExpired, true);
    assert.equal(expiredDeadline.remainingSeconds, 0);

    const examUser = await registerEmailPasswordUser(
      `exam.audit.${TEST_RUN_ID}@medatlas.test`,
      'ExamStudentPass123!',
      'Exam Audit Student'
    );
    createdUserUids.push(examUser.uid);

    const [subj] = await db
      .insert(subjects)
      .values({
        slug: `sec-subj-${TEST_RUN_ID}`,
        title: `Security Audit Subject ${TEST_RUN_ID}`,
        description: 'Temporary subject for exam security regression test',
        displayOrder: 99,
        status: 'published',
      })
      .returning();
    createdSubjectIds.push(subj.id);

    const [lect] = await db
      .insert(lectures)
      .values({
        subjectId: subj.id,
        title: `Security Audit Lecture ${TEST_RUN_ID}`,
        description: 'Temporary lecture',
        lectureNumber: 1,
        status: 'published',
      })
      .returning();
    createdLectureIds.push(lect.id);

    const [q1] = await db
      .insert(questions)
      .values({
        subjectId: subj.id,
        lectureId: lect.id,
        questionText: 'Which cardiac ion channel mediates Phase 0 in SA nodal cells?',
        optionA: 'Fast Na+ channel',
        optionB: 'L-type Ca2+ channel',
        optionC: 'Delayed rectifier K+ channel',
        optionD: 'Funny current Na+/K+ channel',
        correctAnswer: 'B',
        explanation: 'L-type Ca2+ channels mediate Phase 0 in pacemaker nodal tissue.',
        difficulty: 'Medium',
        status: 'published',
        contentHash: `hash_q1_${TEST_RUN_ID}`,
      })
      .returning();
    createdQuestionIds.push(q1.id);

    const [q2] = await db
      .insert(questions)
      .values({
        subjectId: subj.id,
        lectureId: lect.id,
        questionText: 'Which organelle catalyzes O-linked glycosylation?',
        optionA: 'Golgi apparatus',
        optionB: 'Peroxisome',
        optionC: 'Rough ER',
        optionD: 'Lysosome',
        correctAnswer: 'A',
        explanation: 'The Golgi apparatus catalyzes O-linked glycosylation.',
        difficulty: 'Easy',
        status: 'published',
        contentHash: `hash_q2_${TEST_RUN_ID}`,
      })
      .returning();
    createdQuestionIds.push(q2.id);

    const [draftQ] = await db
      .insert(questions)
      .values({
        subjectId: subj.id,
        lectureId: lect.id,
        questionText: 'Unpublished draft question that students must not bookmark',
        optionA: 'A',
        optionB: 'B',
        optionC: 'C',
        optionD: 'D',
        correctAnswer: 'A',
        explanation: 'Draft explanation',
        difficulty: 'Hard',
        status: 'draft',
        contentHash: `hash_draft_${TEST_RUN_ID}`,
      })
      .returning();
    createdQuestionIds.push(draftQ.id);

    // P7: Bookmarking an unpublished (draft) question must fail with 404
    await assert.rejects(
      async () => {
        await toggleBookmarkForStudent(examUser.uid, draftQ.id);
      },
      (err: any) => err instanceof ClientSafeError && err.statusCode === 404
    );

    // Bookmarking a published question succeeds
    const bmRes = await toggleBookmarkForStudent(examUser.uid, q1.id);
    assert.equal(bmRes.bookmarked, true);

    const orderItems = [
      {
        questionId: q1.id,
        permutation: { A: 'A', B: 'B', C: 'C', D: 'D' },
        selectedDisplayed: 'B',
        selectedCanonical: 'B',
        submitted: false,
      },
      {
        questionId: q2.id,
        permutation: { A: 'A', B: 'B', C: 'C', D: 'D' },
        selectedDisplayed: null,
        selectedCanonical: null,
        submitted: false,
      },
    ];

    const [activeExam] = await db
      .insert(examSessions)
      .values({
        userUid: examUser.uid,
        title: 'Concurrent Completion Test Exam',
        mode: 'exam',
        subjectId: subj.id,
        lectureId: lect.id,
        status: 'in_progress',
        totalQuestions: 2,
        unansweredCount: 1,
        timeLimitSeconds: 300,
        elapsedSeconds: 10,
        questionOrderJson: JSON.stringify(orderItems),
        startedAt: new Date(Date.now() - 10_000),
      })
      .returning();
    createdSessionIds.push(activeExam.id);

    const [resA, resB, resC] = await Promise.all([
      completeExamSession(examUser.uid, activeExam.id, { [q1.id]: 'B', [q2.id]: 'A' }, 1),
      completeExamSession(examUser.uid, activeExam.id, { [q1.id]: 'B', [q2.id]: 'A' }, 1),
      completeExamSession(examUser.uid, activeExam.id, { [q1.id]: 'B', [q2.id]: 'A' }, 1),
    ]);

    assert.equal(resA.status, 'completed');
    assert.equal(resB.status, 'completed');
    assert.equal(resC.status, 'completed');
    assert.equal(resA.correctCount, 2);
    assert.ok(resA.elapsedSeconds >= 9, `Expected server elapsed >= 9s, got ${resA.elapsedSeconds}`);

    const attemptsInDb = await db
      .select()
      .from(questionAttempts)
      .where(eq(questionAttempts.sessionId, activeExam.id));
    assert.equal(attemptsInDb.length, 2);

    const [expiredExam] = await db
      .insert(examSessions)
      .values({
        userUid: examUser.uid,
        title: 'Expired Deadline Test Exam',
        mode: 'exam',
        subjectId: subj.id,
        lectureId: lect.id,
        status: 'in_progress',
        totalQuestions: 2,
        unansweredCount: 1,
        timeLimitSeconds: 60,
        elapsedSeconds: 0,
        questionOrderJson: JSON.stringify(orderItems),
        startedAt: new Date(Date.now() - 300_000),
      })
      .returning();
    createdSessionIds.push(expiredExam.id);

    await assert.rejects(
      async () => {
        await saveSessionQuestionAnswer(
          examUser.uid,
          expiredExam.id,
          q2.id,
          'A',
          false,
          5
        );
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 409 &&
        /expired/i.test(err.message)
    );

    await assert.rejects(
      async () => {
        await completeExamSession(
          examUser.uid,
          expiredExam.id,
          { [q1.id]: 'B', [q2.id]: 'A' },
          10
        );
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 409 &&
        /expired/i.test(err.message)
    );
  });

  // ==========================================================================
  // 10. HIGH: ACCOUNT DELETION & ANTI-RESURRECTION ENFORCEMENT
  // ==========================================================================
  it('10. Rejects existing tokens after account deletion and prevents /api/auth/me resurrection', async () => {
    const delEmail = `delete.me.${TEST_RUN_ID}@medatlas.test`;
    const delUser = await registerEmailPasswordUser(
      delEmail,
      'DeleteAccountPass123!',
      'To Be Deleted'
    );
    createdUserUids.push(delUser.uid);

    const tokenBeforeDelete = createServerSessionToken({
      uid: delUser.uid,
      email: delUser.email,
      name: delUser.displayName,
      tokenVersion: delUser.tokenVersion,
    });

    const delResult = await deleteUserAccount(delUser.uid);
    assert.equal(delResult.deleted, true);

    await assert.rejects(
      async () => {
        await getOrCreateUser(delUser.uid, delUser.email, delUser.displayName, {
          authType: 'firebase',
          emailVerified: true,
          allowCreate: true,
        });
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 401 &&
        /deleted/i.test(err.message)
    );

    const remainingUserRows = await db
      .select()
      .from(users)
      .where(eq(users.uid, delUser.uid));
    assert.equal(remainingUserRows.length, 0);

    let authStatus = 200;
    const req = {
      headers: { authorization: `Bearer ${tokenBeforeDelete}` },
    } as unknown as AuthRequest;
    const res = {
      status(code: number) {
        authStatus = code;
        return this;
      },
      json(_body: any) {
        return this;
      },
    } as any;
    let calledNext = false;
    await requireAuth(req, res, () => {
      calledNext = true;
    });
    assert.equal(calledNext, false);
    assert.equal(authStatus, 401);
  });

  // ==========================================================================
  // PRIORITY 6: HARDEN RATE-LIMIT IP HANDLING AGAINST SPOOFED X-FORWARDED-FOR
  // ==========================================================================
  it('P6. Enforces request rate limits, ignores spoofed X-Forwarded-For headers, prunes expired entries, and caps memory at maxKeys', async () => {
    assert.equal(resolveTrustProxyConfig({ TRUST_PROXY_HOPS: '0' } as any), false);
    assert.equal(resolveTrustProxyConfig({ TRUST_PROXY_HOPS: 'false' } as any), false);
    assert.equal(resolveTrustProxyConfig({ TRUST_PROXY_HOPS: '2' } as any), 2);

    // Verify normalizeClientIp ignores raw spoofed X-Forwarded-For when trust proxy is disabled
    const spoofedDirectReq = {
      ip: '10.20.30.40',
      headers: { 'x-forwarded-for': '203.0.113.99, 198.51.100.1' },
      socket: { remoteAddress: '::ffff:192.168.10.5' },
      app: {
        get(setting: string) {
          return setting === 'trust proxy' ? false : undefined;
        },
      },
    } as any;
    assert.equal(
      normalizeClientIp(spoofedDirectReq),
      '192.168.10.5',
      'When trust proxy is false, normalizeClientIp must use socket.remoteAddress and ignore X-Forwarded-For'
    );

    const limiter = createBoundedRateLimiter({
      scope: 'unit-test-limiter',
      windowMs: 2_000,
      maxRequests: 3,
      maxKeys: 25,
    });

    const makeMockPair = (socketIp: string, spoofedXff?: string, body?: any) => {
      let statusCode = 200;
      const headers: Record<string, string> = {};
      const req = {
        ip: socketIp,
        body: body || {},
        headers: spoofedXff ? { 'x-forwarded-for': spoofedXff } : {},
        baseUrl: '/api/auth',
        path: '/login',
        socket: { remoteAddress: socketIp },
        app: {
          get(setting: string) {
            return setting === 'trust proxy' ? false : undefined;
          },
        },
      } as any;
      const res = {
        setHeader(k: string, v: string) {
          headers[k] = v;
        },
        status(code: number) {
          statusCode = code;
          return this;
        },
        json(payload: any) {
          return { statusCode, payload };
        },
      } as any;
      return { req, res, getStatus: () => statusCode, headers };
    };

    // Attacker sends 4 requests from the same socket IP (10.0.0.1) while rotating spoofed X-Forwarded-For headers
    for (let i = 1; i <= 3; i++) {
      const { req, res, getStatus } = makeMockPair('10.0.0.1', `203.0.113.${i}`);
      let nextCalled = false;
      await limiter(req, res, () => {
        nextCalled = true;
      });
      assert.equal(nextCalled, true);
      assert.equal(getStatus(), 200);
    }

    // 4th request from 10.0.0.1 with a brand-new spoofed X-Forwarded-For MUST still be blocked (429)
    const fourth = makeMockPair('10.0.0.1', '198.51.100.250');
    let fourthNext = false;
    await limiter(fourth.req, fourth.res, () => {
      fourthNext = true;
    });
    assert.equal(fourthNext, false);
    assert.equal(fourth.getStatus(), 429);
    assert.ok(Number(fourth.headers['Retry-After']) >= 1);

    for (let i = 0; i < 100; i++) {
      const { req, res } = makeMockPair(`192.168.1.${i}`);
      await limiter(req, res, () => {});
      assert.ok(
        limiter.getStoreSize() <= 25,
        `Rate limiter exceeded maxKeys: ${limiter.getStoreSize()}`
      );
    }

    const removed = await limiter.pruneExpired(Date.now() + 10_000);
    assert.equal(removed, 25);
    assert.equal(limiter.getStoreSize(), 0);
  });

  // ==========================================================================
  // PRIORITY 5: REPLACE REGEX-ONLY SVG SANITIZATION WITH STRICT ALLOWLIST PARSER
  // ==========================================================================
  it('P5. Strips standard, event-handler, foreignObject, URI, CSS, and entity-obfuscated/nested XSS payloads while preserving valid medical SVGs', () => {
    // 1–4: <script>, event handlers, <foreignObject>, and javascript:/data: URIs
    const maliciousSvg = `
      <svg viewBox="0 0 100 100" onload="alert('xss')" xmlns:xlink="http://www.w3.org/1999/xlink">
        <script>window.stealToken()</script>
        <foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject>
        <a href="javascript:evil()" xlink:href="data:text/html,<script>alert(1)</script>">
          <circle cx="50" cy="50" r="40" onclick="evil()" onbegin="evil()" fill="#0284C7" />
        </a>
      </svg>
    `;
    const clean1 = sanitizeSvgDiagram(maliciousSvg);
    assert.ok(!/<script/i.test(clean1));
    assert.ok(!/<foreignObject/i.test(clean1));
    assert.ok(!/<iframe/i.test(clean1));
    assert.ok(!/<a[\s>]/i.test(clean1));
    assert.ok(!/onload/i.test(clean1));
    assert.ok(!/onclick/i.test(clean1));
    assert.ok(!/onbegin/i.test(clean1));
    assert.ok(!/javascript:/i.test(clean1));
    assert.ok(!/data:text\/html/i.test(clean1));

    // 5 & 6: Obfuscated/entity-encoded URIs, nested <script><script>, and malicious inline CSS styles
    const obfuscatedSvg = `
      <svg viewBox="0 0 200 100">
        <script><script>alert(1)</script></script>
        <use href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)" />
        <image xlink:href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(2)" />
        <animate attributeName="href" to="javascript:alert(3)" />
        <set attributeName="onload" to="alert(4)" />
        <rect x="10" y="10" width="80" height="40" style="fill: #0284C7; background-image: url(javascript:alert(5)); width: expression(alert(6));" />
        <text x="20" y="35" fill="#ffffff">AV Node</text>
      </svg>
    `;
    const clean2 = sanitizeSvgDiagram(obfuscatedSvg);
    assert.ok(!/<script/i.test(clean2));
    assert.ok(!/<use/i.test(clean2));
    assert.ok(!/<image/i.test(clean2));
    assert.ok(!/<animate/i.test(clean2));
    assert.ok(!/<set/i.test(clean2));
    assert.ok(!/javascript/i.test(clean2));
    assert.ok(!/expression\s*\(/i.test(clean2));
    assert.ok(!/url\s*\(/i.test(clean2));
    assert.ok(clean2.includes('style="fill: #0284C7"'));
    assert.ok(clean2.includes('<text x="20" y="35" fill="#ffffff">AV Node</text>'));
  });

  // ==========================================================================
  // FINDING 1: PASSWORD RECOVERY CONSISTENCY BETWEEN FIREBASE AND POSTGRESQL
  // ==========================================================================
  it('R1. Supports custom action-handler URL extraction, handles provider 503 and DB commit failures safely, and synchronizes out-of-band Firebase hosted resets while invalidating old local passwords and sessions', async () => {
    const email = `r1.recovery.${TEST_RUN_ID}@medatlas.test`;
    const oldPass = 'R1InitialPassword123!';
    const newPassViaUrl = 'R1UrlExtractedPassword456!';
    const newPassHosted = 'R1HostedFirebaseResetPass789!';

    const user = await registerEmailPasswordUser(email, oldPass, 'R1 Recovery Student');
    createdUserUids.push(user.uid);

    // 1. Verify extractRecoveryCodeFromInput handles both raw oobCodes and full pasted reset URLs
    const rawOob = 'oob_action_code_valid_9876543210_abcdef';
    const fullResetUrl = `https://medatlas.ai.studio/?mode=resetPassword&oobCode=${encodeURIComponent(rawOob)}&apiKey=AIzaTestKey`;
    assert.equal(extractRecoveryCodeFromInput(rawOob), rawOob);
    assert.equal(extractRecoveryCodeFromInput(fullResetUrl), rawOob);

    // 2. Provider 503 outage during OOB verification fails safely with 503 and leaves credentials intact
    setFirebaseOobHandlerForTests({
      verifyOnly: async () => {
        throw new ClientSafeError(
          'Password recovery service is temporarily unavailable. Please try again shortly.',
          503
        );
      },
      consume: async () => {
        throw new Error('Consume must not run on 503');
      },
    });
    try {
      await assert.rejects(
        async () => confirmPasswordRecoveryToken(fullResetUrl, newPassViaUrl),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 503
      );
    } finally {
      setFirebaseOobHandlerForTests(null);
    }

    // 3. Database commit failure AFTER OOB code consumption rolls back transaction, throws error (never claims success),
    // and leaves `pendingRecoveryAt` set so the old local password cannot be used while allowing Firebase sync on login.
    let oobConsumedInFailedTx = false;
    setFirebaseOobHandlerForTests({
      verifyOnly: async () => ({ email }),
      consume: async () => {
        oobConsumedInFailedTx = true;
        return { email };
      },
    });
    try {
      await assert.rejects(
        async () =>
          confirmPasswordRecoveryToken(fullResetUrl, newPassViaUrl, {
            simulateDbFailureAfterConsumeForTests: async () => {
              throw new Error('Simulated DB commit failure after OOB consume');
            },
          }),
        /Failed to reset password/i
      );
      assert.equal(oobConsumedInFailedTx, true);
    } finally {
      setFirebaseOobHandlerForTests(null);
    }

    const userAfterFailedTx = await findUserByEmail(email);
    assert.ok(
      userAfterFailedTx?.pendingRecoveryAt,
      'pendingRecoveryAt must remain set when DB commit fails after OOB consumption'
    );

    // 4. Out-of-band Firebase hosted reset (or recovery after partial failure during active pendingRecoveryAt window):
    // Initiate a fresh recovery request so `pendingRecoveryAt` is active
    setFirebaseProvisioningHandlerForTests(async () => ({
      provisioned: true,
      firebaseUid: `fb_shadow_${TEST_RUN_ID}`,
    }));
    setFirebaseEmailDispatchHandlerForTests(async (_em, continueUrl) => {
      assert.equal(continueUrl, 'https://medatlas.ai.studio/?mode=resetPassword');
      return true;
    });
    try {
      const reqRes = await requestPasswordRecoveryToken(email, {
        origin: 'https://medatlas.ai.studio',
        triggerFirebaseEmail: true,
      });
      assert.equal(reqRes.deliveryChannel, 'firebase');
    } finally {
      setFirebaseProvisioningHandlerForTests(null);
      setFirebaseEmailDispatchHandlerForTests(null);
    }

    const oldTokenBeforeHostedReset = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
      tokenVersion: user.tokenVersion,
    });

    // Simulate user completing the password reset on Firebase's hosted page (so Firebase now only accepts `newPassHosted`)
    setFirebasePasswordVerifyHandlerForTests(async (_em, candidatePass) => ({
      valid: candidatePass === newPassHosted,
      firebaseUid: `fb_shadow_${TEST_RUN_ID}`,
      definiteRejection: candidatePass !== newPassHosted,
    }));

    try {
      // Old local password MUST BE REJECTED because `pendingRecoveryAt` is active and Firebase definitively rejects `oldPass`
      const oldPassAttempt = await authenticateEmailUser(email, oldPass);
      assert.equal(
        oldPassAttempt,
        null,
        'Old local password must be rejected when user reset password via Firebase hosted flow'
      );

      // New password set on Firebase hosted page succeeds, synchronizes PostgreSQL hash, clears pendingRecoveryAt, and revokes old sessions!
      const syncedUser = await authenticateEmailUser(email, newPassHosted);
      assert.ok(syncedUser, 'New Firebase password must authenticate and synchronize local DB');
      assert.ok(syncedUser.tokenVersion > user.tokenVersion);
      assert.equal(syncedUser.pendingRecoveryAt, null);
      assert.equal(syncedUser.firebaseUid, `fb_shadow_${TEST_RUN_ID}`);
      assert.equal(await verifyPasswordAsync(newPassHosted, syncedUser.passwordHash!), true);
      assert.equal(await verifyPasswordAsync(oldPass, syncedUser.passwordHash!), false);
    } finally {
      setFirebasePasswordVerifyHandlerForTests(null);
    }

    // Old session token issued before hosted reset synchronization must now be rejected (401)
    let oldSessionStatus = 200;
    const req = {
      headers: { authorization: `Bearer ${oldTokenBeforeHostedReset}` },
    } as unknown as AuthRequest;
    const res = {
      status(c: number) {
        oldSessionStatus = c;
        return this;
      },
      json() {
        return this;
      },
    } as any;
    let nextCalled = false;
    await requireAuth(req, res, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, false);
    assert.equal(oldSessionStatus, 401);
  });

  // ==========================================================================
  // FINDING 2: FIX PASSWORD-CHANGE CREDENTIAL DIVERGENCE
  // ==========================================================================
  it('R2. Synchronizes authenticated password changes to Firebase, fails closed when provider update fails, and never lets a stale Firebase password overwrite a newer local password', async () => {
    const email = `r2.divergence.${TEST_RUN_ID}@medatlas.test`;
    const initialPass = 'R2InitialPassword123!';
    const changedPass = 'R2ChangedPassword456!';

    const user = await registerEmailPasswordUser(email, initialPass, 'R2 Student');
    createdUserUids.push(user.uid);

    // Attach a firebaseUid so the account is a linked hybrid account
    await db
      .update(users)
      .set({ firebaseUid: `fb_r2_${TEST_RUN_ID}`, authProvider: 'both' })
      .where(eq(users.uid, user.uid));

    // 1. If Firebase provider password sync fails during changeAuthenticatedUserPassword, it must fail closed (503)
    // and NOT modify the PostgreSQL passwordHash.
    setFirebasePasswordUpdateHandlerForTests(async () => false);
    try {
      await assert.rejects(
        async () => changeAuthenticatedUserPassword(user.uid, initialPass, changedPass),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 503
      );
    } finally {
      setFirebasePasswordUpdateHandlerForTests(null);
    }

    // Verify initial password still works after failed provider sync
    const afterFailedChange = await authenticateEmailUser(email, initialPass);
    assert.ok(afterFailedChange);

    // 2. When Firebase provider sync succeeds, changeAuthenticatedUserPassword updates PostgreSQL,
    // updates passwordUpdatedAt, clears pendingRecoveryAt, and increments tokenVersion.
    let syncedToFirebaseNewPass = '';
    setFirebasePasswordUpdateHandlerForTests(async (params) => {
      syncedToFirebaseNewPass = params.newPassword;
      return true;
    });
    try {
      const updated = await changeAuthenticatedUserPassword(
        user.uid,
        initialPass,
        changedPass
      );
      assert.equal(syncedToFirebaseNewPass, changedPass);
      assert.ok(updated.passwordUpdatedAt);
      assert.equal(updated.pendingRecoveryAt, null);
    } finally {
      setFirebasePasswordUpdateHandlerForTests(null);
    }

    // 3. Even if Firebase Auth somehow still accepted the OLD password (`initialPass`),
    // `authenticateEmailUser` MUST reject `initialPass` and NEVER overwrite the newer local password hash!
    setFirebasePasswordVerifyHandlerForTests(async (_em, candidatePass) => ({
      valid: candidatePass === initialPass, // Simulate stale provider accepting old password
      firebaseUid: `fb_r2_${TEST_RUN_ID}`,
      definiteRejection: false,
    }));
    try {
      const staleAttempt = await authenticateEmailUser(email, initialPass);
      assert.equal(
        staleAttempt,
        null,
        'Stale provider password must NEVER authenticate or overwrite a newer local password'
      );

      // And the new password (`changedPass`) continues to authenticate via authoritative PostgreSQL hash
      const validNewAttempt = await authenticateEmailUser(email, changedPass);
      assert.ok(validNewAttempt);
      assert.equal(validNewAttempt.uid, user.uid);
    } finally {
      setFirebasePasswordVerifyHandlerForTests(null);
    }
  });

  // ==========================================================================
  // FINDING 3: FAIL SAFELY WHEN CHECKING FIREBASE TOKEN REVOCATION
  // ==========================================================================
  it('R3. Fails closed on revoked, disabled, expired, generic Firebase errors, and network timeouts while allowing narrow config fallback only when live/DB state is verified', async () => {
    const fbUid = `fb_r3_revocation_${TEST_RUN_ID}`;
    const fbEmail = `r3.revocation.${TEST_RUN_ID}@medatlas.test`;
    createdUserUids.push(fbUid);

    await getOrCreateUser(fbUid, fbEmail, 'R3 Revocation User', {
      authType: 'firebase',
      emailVerified: true,
      allowCreate: true,
    });

    const callRequireAuth = async () => {
      let status = 200;
      let nextCalled = false;
      const req = {
        headers: { authorization: 'Bearer mock.r3.firebase.token' },
      } as unknown as AuthRequest;
      const res = {
        status(code: number) {
          status = code;
          return this;
        },
        json() {
          return this;
        },
      } as any;
      await requireAuth(req, res, () => {
        nextCalled = true;
      });
      return { status, nextCalled };
    };

    const nowSec = Math.floor(Date.now() / 1000);

    try {
      // 1. Explicitly revoked token -> 401
      setFirebaseTokenVerifierForTests(async () => {
        const err: any = new Error('Revoked');
        err.code = 'auth/id-token-revoked';
        throw err;
      });
      assert.deepEqual(await callRequireAuth(), { status: 401, nextCalled: false });

      // 2. Disabled user -> 403
      setFirebaseTokenVerifierForTests(async () => {
        const err: any = new Error('Disabled');
        err.code = 'auth/user-disabled';
        throw err;
      });
      assert.deepEqual(await callRequireAuth(), { status: 403, nextCalled: false });

      // 3. Expired token -> 401
      setFirebaseTokenVerifierForTests(async () => {
        const err: any = new Error('Expired');
        err.code = 'auth/id-token-expired';
        throw err;
      });
      assert.deepEqual(await callRequireAuth(), { status: 401, nextCalled: false });

      // 4. Generic Firebase internal error -> fails closed with 503 (never falls back to checkRevoked=false)
      setFirebaseTokenVerifierForTests(async (_token, checkRevoked) => {
        if (checkRevoked) {
          const err: any = new Error('Internal Firebase failure');
          err.code = 'auth/internal-error';
          throw err;
        }
        throw new Error('Must NOT call verifyIdToken(token, false) on generic internal error');
      });
      assert.deepEqual(await callRequireAuth(), { status: 503, nextCalled: false });

      // 5. Network timeout -> fails closed with 503
      setFirebaseTokenVerifierForTests(async (_token, checkRevoked) => {
        if (checkRevoked) {
          const err: any = new Error('connect ETIMEDOUT');
          err.code = 'ETIMEDOUT';
          throw err;
        }
        throw new Error('Must NOT call verifyIdToken(token, false) on network timeout');
      });
      assert.deepEqual(await callRequireAuth(), { status: 503, nextCalled: false });

      // 6. Unexpected IAM permission error -> fails closed with 503
      setFirebaseTokenVerifierForTests(async (_token, checkRevoked) => {
        if (checkRevoked) {
          const err: any = new Error('Insufficient permission');
          err.code = 'auth/insufficient-permission';
          throw err;
        }
        throw new Error('Must NOT call verifyIdToken(token, false) on permission error');
      });
      assert.deepEqual(await callRequireAuth(), { status: 503, nextCalled: false });

      // 7. Narrow ADC configuration absence (`app/invalid-credential`) with live lookup verifying active user -> 200
      setFirebaseTokenVerifierForTests(async (_token, checkRevoked) => {
        if (checkRevoked) {
          const err: any = new Error('Could not load the default credentials');
          err.code = 'app/invalid-credential';
          throw err;
        }
        return {
          uid: fbUid,
          email: fbEmail,
          name: 'R3 Revocation User',
          email_verified: true,
          iat: nowSec,
          auth_time: nowSec,
        };
      });
      setFirebaseLookupRestHandlerForTests(async () => ({
        status: 'ok',
        disabled: false,
        validSinceSec: nowSec - 60,
      }));
      assert.deepEqual(await callRequireAuth(), { status: 200, nextCalled: true });

      // If live lookup reports disabled user during narrow config fallback -> 403
      setFirebaseLookupRestHandlerForTests(async () => ({
        status: 'ok',
        disabled: true,
        validSinceSec: nowSec - 60,
      }));
      assert.deepEqual(await callRequireAuth(), { status: 403, nextCalled: false });

      // If live lookup reports validSince newer than token iat -> 401
      setFirebaseLookupRestHandlerForTests(async () => ({
        status: 'ok',
        disabled: false,
        validSinceSec: nowSec + 120,
      }));
      assert.deepEqual(await callRequireAuth(), { status: 401, nextCalled: false });
    } finally {
      setFirebaseTokenVerifierForTests(null);
      setFirebaseLookupRestHandlerForTests(null);
    }
  });

  // ==========================================================================
  // FINDING 4: ACCOUNT DELETION, FIREBASE IDENTITY MAPPING & TOMBSTONE HANDLING
  // ==========================================================================
  it('R4. Properly maps and cleans up Firebase shadow/provider identities on deletion, preserves deleted UID/firebaseUid tombstones across re-registration, blocks credential fallback for deleted identities, and isolates new accounts', async () => {
    const email = `r4.lifecycle.${TEST_RUN_ID}@medatlas.test`;
    const shadowFbUid = `fb_shadow_r4_${TEST_RUN_ID}`;
    const initialPass = 'R4LifecyclePass123!';

    // 1. Register a local account and attach a Firebase shadow identity + a bookmark record
    const originalUser = await registerEmailPasswordUser(
      email,
      initialPass,
      'Original R4 User'
    );
    createdUserUids.push(originalUser.uid);

    await db
      .update(users)
      .set({ firebaseUid: shadowFbUid, authProvider: 'both' })
      .where(eq(users.uid, originalUser.uid));

    // Clear any pending_retry tombstones from prior aborted test runs
    await db
      .update(deletedAccounts)
      .set({ remoteCleanupStatus: 'completed' })
      .where(eq(deletedAccounts.remoteCleanupStatus, 'pending_retry'));

    // Simulate remote cleanup failing first (`pending_retry`), then succeeding via `reconcilePendingDeletedAccounts()`
    let remoteDeleteAttempts = 0;
    setFirebaseAccountDeletionHandlerForTests(async (params) => {
      if (params.firebaseUid === shadowFbUid) {
        remoteDeleteAttempts++;
        if (remoteDeleteAttempts === 1) {
          return { deleted: false, errorCode: 'SIMULATED_TRANSIENT_FIREBASE_ERROR' };
        }
        return { deleted: true };
      }
      return { deleted: true };
    });

    try {
      const delRes = await deleteUserAccount(originalUser.uid);
      assert.equal(delRes.deleted, true);
      assert.equal(delRes.remoteCleanupStatus, 'pending_retry');

      const reconcileRes = await reconcilePendingDeletedAccounts();
      assert.ok(reconcileRes.reconciled >= 1);

      const [tombstoneAfterReconcile] = await db
        .select()
        .from(deletedAccounts)
        .where(eq(deletedAccounts.uid, originalUser.uid));
      assert.ok(tombstoneAfterReconcile);
      assert.equal(tombstoneAfterReconcile.firebaseUid, shadowFbUid);
      assert.equal(tombstoneAfterReconcile.remoteCleanupStatus, 'completed');
    } finally {
      setFirebaseAccountDeletionHandlerForTests(null);
    }

    // 2. Attempting to use old Firebase password after deletion fails
    setFirebasePasswordVerifyHandlerForTests(async () => ({
      valid: true,
      firebaseUid: shadowFbUid,
      definiteRejection: false,
    }));
    try {
      const loginAfterDelete = await authenticateEmailUser(email, initialPass);
      assert.equal(loginAfterDelete, null);
    } finally {
      setFirebasePasswordVerifyHandlerForTests(null);
    }

    // 3. Re-registering the same email address is permitted under a BRAND-NEW UID,
    // and MUST NOT erase the deleted_accounts tombstone for `originalUser.uid` or `shadowFbUid`!
    const reRegisteredUser = await registerEmailPasswordUser(
      email,
      'R4BrandNewPass456!',
      'Re-Registered R4 User'
    );
    createdUserUids.push(reRegisteredUser.uid);
    assert.notEqual(reRegisteredUser.uid, originalUser.uid);
    assert.equal(reRegisteredUser.role, 'student');
    assert.equal(reRegisteredUser.firebaseUid, null);

    // Verify original tombstone STILL EXISTS in `deleted_accounts`
    const [preservedTombstone] = await db
      .select()
      .from(deletedAccounts)
      .where(eq(deletedAccounts.uid, originalUser.uid));
    assert.ok(
      preservedTombstone,
      'Re-registration must NEVER delete the tombstone protecting the old deleted UID and firebaseUid'
    );

    // 4. Attempting to authenticate with the old local UID or old Firebase UID (`shadowFbUid`) after re-registration
    // MUST be rejected with 401 and must NEVER link to or access the new account!
    const staleLocalToken = createServerSessionToken({
      uid: originalUser.uid,
      email,
      name: 'Original R4 User',
      tokenVersion: 1,
    });

    const checkTokenRejected = async (bearer: string) => {
      let status = 200;
      let nextCalled = false;
      const req = {
        headers: { authorization: `Bearer ${bearer}` },
      } as unknown as AuthRequest;
      const res = {
        status(c: number) {
          status = c;
          return this;
        },
        json() {
          return this;
        },
      } as any;
      await requireAuth(req, res, () => {
        nextCalled = true;
      });
      return { status, nextCalled };
    };

    assert.deepEqual(await checkTokenRejected(staleLocalToken), {
      status: 401,
      nextCalled: false,
    });

    const nowSec = Math.floor(Date.now() / 1000);
    setFirebaseTokenVerifierForTests(async () => ({
      uid: shadowFbUid,
      email,
      name: 'Stale Shadow Identity',
      email_verified: true,
      iat: nowSec,
      auth_time: nowSec,
    }));
    try {
      assert.deepEqual(await checkTokenRejected('mock.stale.firebase.jwt'), {
        status: 401,
        nextCalled: false,
      });

      // Also verify `getOrCreateUser` rejects the tombstoned `shadowFbUid` with 401
      await assert.rejects(
        async () =>
          getOrCreateUser(shadowFbUid, email, 'Stale Shadow Identity', {
            authType: 'firebase',
            emailVerified: true,
            allowCreate: true,
          }),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 401
      );
    } finally {
      setFirebaseTokenVerifierForTests(null);
    }

    // 5. Credential fallback attempt using the old tombstoned `shadowFbUid` during a recovery window on the new account
    // MUST be rejected and never overwrite the new account's password!
    await db
      .update(users)
      .set({ pendingRecoveryAt: new Date() })
      .where(eq(users.uid, reRegisteredUser.uid));

    setFirebasePasswordVerifyHandlerForTests(async () => ({
      valid: true,
      firebaseUid: shadowFbUid, // Tombstoned Firebase UID from the deleted user!
      definiteRejection: false,
    }));
    try {
      const hijackedAttempt = await authenticateEmailUser(email, initialPass);
      assert.equal(
        hijackedAttempt,
        null,
        'Deleted Firebase UID must never overwrite credentials on a re-registered account'
      );
    } finally {
      setFirebasePasswordVerifyHandlerForTests(null);
    }
  });

  // ==========================================================================
  // FINDING 5: RESTRICT PASSWORD-RECOVERY ORIGINS
  // ==========================================================================
  it('R5. Enforces strict origin allowlist, rejects arbitrary *.ai.studio and *.run.app origins, blocks HTTP in production, and rejects paths/queries/fragments/credentials', () => {
    const savedAllowed = process.env.ALLOWED_RECOVERY_ORIGINS;
    const savedAppUrl = process.env.APP_URL;
    try {
      process.env.APP_URL = 'https://medatlas.ai.studio';
      process.env.ALLOWED_RECOVERY_ORIGINS = 'https://custom-trusted.medatlas.org';

      // Allowed origins
      assert.equal(
        validateTrustedRecoveryOrigin('https://medatlas.ai.studio'),
        'https://medatlas.ai.studio'
      );
      assert.equal(
        validateTrustedRecoveryOrigin('https://custom-trusted.medatlas.org'),
        'https://custom-trusted.medatlas.org'
      );
      assert.equal(
        validateTrustedRecoveryOrigin('http://localhost:3000', { nodeEnv: 'development' }),
        'http://localhost:3000'
      );

      // HTTP localhost rejected in production
      assert.throws(
        () => validateTrustedRecoveryOrigin('http://localhost:3000', { nodeEnv: 'production' }),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );

      // Arbitrary *.ai.studio and *.run.app rejected
      assert.throws(
        () => validateTrustedRecoveryOrigin('https://untrusted-other-applet.ai.studio'),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );
      assert.throws(
        () => validateTrustedRecoveryOrigin('https://untrusted-other-service.run.app'),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );

      // Paths, query strings, fragments, and credentials rejected
      assert.throws(
        () => validateTrustedRecoveryOrigin('https://medatlas.ai.studio/evil'),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );
      assert.throws(
        () => validateTrustedRecoveryOrigin('https://medatlas.ai.studio?next=evil.com'),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );
      assert.throws(
        () => validateTrustedRecoveryOrigin('https://medatlas.ai.studio#frag'),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );
      assert.throws(
        () => validateTrustedRecoveryOrigin('https://user:pass@medatlas.ai.studio'),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 400
      );
    } finally {
      if (savedAllowed === undefined) delete process.env.ALLOWED_RECOVERY_ORIGINS;
      else process.env.ALLOWED_RECOVERY_ORIGINS = savedAllowed;
      if (savedAppUrl === undefined) delete process.env.APP_URL;
      else process.env.APP_URL = savedAppUrl;
    }
  });

  // ==========================================================================
  // FINDING 6: SHARED POSTGRESQL RATE LIMITING, INDEPENDENT IP/EMAIL LIMITS & ANTI-CHURN
  // ==========================================================================
  it('R6. Shares rate-limit counters across instances via PostgreSQL, enforces independent IP and email limits, protects active multi-hit blocks from single-hit key churn, and handles store failures gracefully', async () => {
    // 1. Protect active multi-hit counters (`count > 1`) from high-cardinality single-hit (`count === 1`) key churn
    const antiChurnLimiter = createBoundedRateLimiter({
      scope: `r6-churn-${TEST_RUN_ID}`,
      windowMs: 60_000,
      maxRequests: 3,
      maxKeys: 10,
    });

    const invokeLimiter = async (
      limiterFn: ReturnType<typeof createBoundedRateLimiter>,
      ip: string,
      email?: string
    ) => {
      let status = 200;
      let nextCalled = false;
      const req = {
        ip,
        body: email ? { email } : {},
        headers: {},
        socket: { remoteAddress: ip },
        app: { get: () => false },
      } as any;
      const res = {
        setHeader() {},
        status(c: number) {
          status = c;
          return this;
        },
        json() {
          return this;
        },
      } as any;
      await limiterFn(req, res, () => {
        nextCalled = true;
      });
      return { status, nextCalled };
    };

    // Target attacker IP `10.99.0.1` hits 3 times (reaching maxRequests = 3, count = 3 > 1)
    for (let i = 0; i < 3; i++) {
      const r = await invokeLimiter(antiChurnLimiter, '10.99.0.1');
      assert.equal(r.status, 200);
    }
    // 4th hit is 429
    assert.equal((await invokeLimiter(antiChurnLimiter, '10.99.0.1')).status, 429);

    // Now flood the limiter with 50 unique single-hit keys (`count === 1`) exceeding `maxKeys: 10`
    for (let i = 0; i < 50; i++) {
      await invokeLimiter(antiChurnLimiter, `10.88.0.${i}`);
    }

    // Verify `10.99.0.1` WAS NOT EVICTED by the single-hit key churn and is STILL blocked (429)!
    const afterChurn = await invokeLimiter(antiChurnLimiter, '10.99.0.1');
    assert.equal(
      afterChurn.status,
      429,
      'Active multi-hit rate-limit counter must NOT be evicted by single-hit key churn'
    );

    // 2. Shared PostgreSQL rate-limit store across two independent limiter instances + secondary per-email rule
    const pgStore = createPostgresRateLimitStore();
    const scopeName = `r6-pg-shared-${TEST_RUN_ID}`;
    const instanceA = createBoundedRateLimiter({
      scope: scopeName,
      windowMs: 60_000,
      maxRequests: 5,
      maxKeys: 100,
      store: pgStore,
      keyGenerator: (req) => `${normalizeClientIp(req)}:${req.body?.email || ''}`,
      secondaryRules: [
        {
          scopeSuffix: 'email',
          maxRequests: 3,
          keyGenerator: (req) => req.body?.email || null,
        },
      ],
    });
    const instanceB = createBoundedRateLimiter({
      scope: scopeName,
      windowMs: 60_000,
      maxRequests: 5,
      maxKeys: 100,
      store: pgStore,
      keyGenerator: (req) => `${normalizeClientIp(req)}:${req.body?.email || ''}`,
      secondaryRules: [
        {
          scopeSuffix: 'email',
          maxRequests: 3,
          keyGenerator: (req) => req.body?.email || null,
        },
      ],
    });

    const targetEmail = `victim.${TEST_RUN_ID}@medatlas.test`;
    // Hit 1 on Instance A from IP 1, Hit 2 on Instance B from IP 2, Hit 3 on Instance A from IP 3
    assert.equal((await invokeLimiter(instanceA, '10.1.0.1', targetEmail)).status, 200);
    assert.equal((await invokeLimiter(instanceB, '10.1.0.2', targetEmail)).status, 200);
    assert.equal((await invokeLimiter(instanceA, '10.1.0.3', targetEmail)).status, 200);

    // Hit 4 on Instance B from a brand-new IP 4 targeting the same email MUST be blocked (429) by the shared email secondary rule!
    const fourthAcrossInstances = await invokeLimiter(instanceB, '10.1.0.4', targetEmail);
    assert.equal(
      fourthAcrossInstances.status,
      429,
      'Shared PostgreSQL store and secondary per-email limit must block distributed attacks across instances and IPs'
    );

    // Clean up test rate limit buckets
    await db
      .delete(rateLimitBuckets)
      .where(
        inArray(rateLimitBuckets.key, [
          `${scopeName}:10.1.0.1:${targetEmail}`,
          `${scopeName}:10.1.0.2:${targetEmail}`,
          `${scopeName}:10.1.0.3:${targetEmail}`,
          `${scopeName}:10.1.0.4:${targetEmail}`,
          `${scopeName}:email:${targetEmail}`,
        ])
      );

    // 3. Degraded-mode fallback when backing store throws an error
    const brokenStore = {
      consume: async () => {
        throw new Error('Simulated DB connection outage');
      },
      pruneExpired: async () => 0,
    };
    const resilientLimiter = createBoundedRateLimiter({
      scope: `r6-fallback-${TEST_RUN_ID}`,
      windowMs: 60_000,
      maxRequests: 2,
      maxKeys: 20,
      store: brokenStore,
    });
    assert.equal((await invokeLimiter(resilientLimiter, '10.55.0.1')).status, 200);
    assert.equal((await invokeLimiter(resilientLimiter, '10.55.0.1')).status, 200);
    assert.equal(
      (await invokeLimiter(resilientLimiter, '10.55.0.1')).status,
      429,
      'In-memory fallback must enforce rate limits when shared store is unreachable'
    );
  });

  // ==========================================================================
  // FINDING 7: DEDICATED SESSION-REVOCATION TIMESTAMP
  // ==========================================================================
  it('R7. Uses dedicated sessionsRevokedAt timestamp so profile updates after tokenVersion > 1 never invalidate active sessions', async () => {
    const email = `r7.sessions.${TEST_RUN_ID}@medatlas.test`;
    const pass1 = 'R7InitialPass123!';
    const pass2 = 'R7SecondPass456!';

    const user = await registerEmailPasswordUser(email, pass1, 'R7 Initial Name');
    createdUserUids.push(user.uid);

    // Increment tokenVersion to 2 via password change
    const afterPassChange = await changeAuthenticatedUserPassword(user.uid, pass1, pass2);
    assert.equal(afterPassChange.tokenVersion, 2);

    // Issue a valid session token at tokenVersion = 2
    const activeTokenV2 = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: afterPassChange.displayName,
      tokenVersion: afterPassChange.tokenVersion,
    });

    // Wait 20ms then update user profile (displayName and preferences)
    await new Promise((r) => setTimeout(r, 20));
    const afterProfileEdit = await updateUserProfile(user.uid, {
      displayName: 'R7 Updated Display Name',
      preferences: { theme: 'light', fontSize: 'medium' },
    });
    assert.equal(afterProfileEdit.displayName, 'R7 Updated Display Name');
    assert.equal(afterProfileEdit.tokenVersion, 2);

    // Verify `activeTokenV2` (and a Firebase token issued before the profile edit) STILL SUCCEED!
    let localStatus = 200;
    let localNext = false;
    await requireAuth(
      { headers: { authorization: `Bearer ${activeTokenV2}` } } as unknown as AuthRequest,
      {
        status(c: number) {
          localStatus = c;
          return this;
        },
        json() {
          return this;
        },
      } as any,
      () => {
        localNext = true;
      }
    );
    assert.equal(
      localNext,
      true,
      'Profile updates after tokenVersion > 1 must NOT invalidate active local sessions'
    );
    assert.equal(localStatus, 200);
  });

  // ==========================================================================
  // FINDING 8: BOUND PASSWORD INPUT AND REDUCE DOS RISK
  // ==========================================================================
  it('R8. Enforces strict password character (128) and byte (512) bounds before scrypt, rejects non-string inputs, and supports Unicode passphrases', async () => {
    assert.equal(MIN_PASSWORD_LENGTH, 8);
    assert.equal(MAX_PASSWORD_LENGTH, 128);
    assert.equal(MAX_PASSWORD_BYTES, 512);

    // Non-string rejected
    assert.equal(validatePasswordBounds(null).valid, false);
    assert.equal(validatePasswordBounds(12345678).valid, false);
    assert.equal(validatePasswordBounds({ password: 'abc' }).valid, false);

    // Too short rejected when requireMinLength = true
    assert.equal(validatePasswordBounds('Short1!', { requireMinLength: true }).valid, false);

    // > 128 characters rejected before scrypt
    const oversizedChars = 'A'.repeat(129);
    const charCheck = validatePasswordBounds(oversizedChars);
    assert.equal(charCheck.valid, false);
    assert.match(charCheck.error || '', /must not exceed 128 characters/i);

    await assert.rejects(
      async () => hashPasswordAsync(oversizedChars),
      /must not exceed 128 characters/i
    );

    const existingHash = await hashPasswordAsync('ValidNormalPass123!');
    assert.equal(await verifyPasswordAsync(oversizedChars, existingHash), false);

    // Unicode passphrase within bounds (e.g. medical terminology + accents/symbols) succeeds
    const unicodePass = 'ClínicaMédica-Histología-2026-αβγ!';
    assert.equal(validatePasswordBounds(unicodePass).valid, true);
    const unicodeHash = await hashPasswordAsync(unicodePass);
    assert.equal(await verifyPasswordAsync(unicodePass, unicodeHash), true);
  });

  // ==========================================================================
  // FINDING 9 & 10: ANTI-ENUMERATION & TEST-HOOK PRODUCTION GUARDS
  // ==========================================================================
  it('R9 & R10. Blocks test-only override hooks when NODE_ENV is production', () => {
    const prevEnv = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      assert.throws(
        () => setFirebaseTokenVerifierForTests(async () => ({ uid: 'x' } as any)),
        /forbidden outside test environment/i
      );
      assert.throws(
        () =>
          setFirebaseOobHandlerForTests({
            verifyOnly: async () => ({ email: 'a@b.c' }),
            consume: async () => ({ email: 'a@b.c' }),
          }),
        /forbidden outside test environment/i
      );
      assert.throws(
        () => setFirebaseProvisioningHandlerForTests(async () => true),
        /forbidden outside test environment/i
      );
      assert.throws(
        () => setFirebaseEmailDispatchHandlerForTests(async () => true),
        /forbidden outside test environment/i
      );
      assert.throws(
        () => setFirebasePasswordUpdateHandlerForTests(async () => true),
        /forbidden outside test environment/i
      );
      assert.throws(
        () => setFirebasePasswordVerifyHandlerForTests(async () => true),
        /forbidden outside test environment/i
      );
      assert.throws(
        () => setFirebaseAccountDeletionHandlerForTests(async () => ({ deleted: true })),
        /forbidden outside test environment/i
      );
      assert.throws(
        () => setSimulateDbFailureAfterProviderSyncForTests(async () => {}),
        /forbidden outside test environment/i
      );
    } finally {
      process.env.NODE_ENV = prevEnv;
    }
  });

  it('F1. Activates shared PostgreSQL rate-limit store under configured production database credentials, enforces documented degraded policy when credentials missing, and never makes false multi-instance claims', async () => {
    const invokeLimiterWithContext = async (
      limiterMiddleware: ReturnType<typeof createBoundedRateLimiter>,
      options?: { ip?: string; email?: string; headers?: Record<string, string>; uid?: string; path?: string }
    ) => {
      const ip = options?.ip || '198.51.100.1';
      let status = 200;
      let body: any = null;
      const headers: Record<string, string> = {};
      let nextCalled = false;

      const req: any = {
        ip,
        body: {
          ...(options?.email ? { email: options.email } : {}),
        },
        headers: options?.headers || {},
        socket: { remoteAddress: ip },
        baseUrl: '',
        path: options?.path || '/api/auth/test',
        user: options?.uid ? { uid: options.uid } : undefined,
        app: { get: () => false },
      };

      const res: any = {
        setHeader(name: string, value: string) {
          headers[name.toLowerCase()] = String(value);
          return this;
        },
        getHeader(name: string) {
          return headers[name.toLowerCase()];
        },
        status(c: number) {
          status = c;
          return this;
        },
        json(payload: any) {
          body = payload;
          return this;
        },
      };

      await limiterMiddleware(req, res, () => {
        nextCalled = true;
      });

      return { status, body, headers, nextCalled };
    };

    // 1. Configured production database credentials (SQL_HOST, SQL_USER, SQL_PASSWORD, SQL_DB_NAME) activate shared store
    const prodConfiguredEnv: NodeJS.ProcessEnv = {
      NODE_ENV: 'production',
      SQL_HOST: '/cloudsql/prod-instance',
      SQL_USER: 'app_user',
      SQL_PASSWORD: 'secret_password',
      SQL_DB_NAME: 'medatlas_db',
    };
    assert.equal(isDatabaseConfigured(prodConfiguredEnv), true);
    const prodResolution = resolveRateLimitStoreConfig(prodConfiguredEnv);
    assert.equal(prodResolution.type, 'shared_postgres');
    assert.ok(prodResolution.store !== undefined, 'Shared store must be attached');
    assert.equal(prodResolution.degradedModePolicy, 'fail_closed');

    // 2. DATABASE_URL also activates shared store
    const dbUrlEnv: NodeJS.ProcessEnv = {
      NODE_ENV: 'production',
      DATABASE_URL: 'postgres://user:pass@host:5432/db',
    };
    assert.equal(isDatabaseConfigured(dbUrlEnv), true);
    const dbUrlResolution = resolveRateLimitStoreConfig(dbUrlEnv);
    assert.equal(dbUrlResolution.type, 'shared_postgres');
    assert.ok(dbUrlResolution.store !== undefined);

    // 3. Unconfigured production environment resolves degraded policy fail_closed with security alert
    const prodMissingEnv: NodeJS.ProcessEnv = {
      NODE_ENV: 'production',
    };
    assert.equal(isDatabaseConfigured(prodMissingEnv), false);
    const missingResolution = resolveRateLimitStoreConfig(prodMissingEnv);
    assert.equal(missingResolution.type, 'memory_fallback');
    assert.equal(missingResolution.store, undefined, 'Must not claim shared multi-instance store when DB unconfigured');
    assert.equal(missingResolution.degradedModePolicy, 'fail_closed');
    assert.ok(missingResolution.warning?.includes('SECURITY ALERT'), 'Must log explicit security alert in production');

    // 4. Production with no database configuration and fail_closed rejects requests with HTTP 503
    const prodMissingLimiter = createBoundedRateLimiter({
      scope: `prod-fail-closed-${TEST_RUN_ID}`,
      windowMs: 60_000,
      maxRequests: 5,
      store: undefined,
      degradedModePolicy: 'fail_closed',
    });
    const res2 = await invokeLimiterWithContext(prodMissingLimiter);
    assert.equal(res2.status, 503);
    assert.equal(res2.nextCalled, false, 'Requests must NOT pass through when store missing under fail_closed');
    assert.equal(res2.headers['x-ratelimit-protection'], 'fail-closed-unavailable');
    assert.match(res2.body?.error || '', /unavailable/i);

    // 5. Production with a shared store that throws also returns HTTP 503 under fail_closed
    const throwingStore = {
      consume: async () => {
        throw new Error('Database pool connection timeout');
      },
      pruneExpired: async () => 0,
    };
    const throwingLimiter = createBoundedRateLimiter({
      scope: `prod-throwing-${TEST_RUN_ID}`,
      windowMs: 60_000,
      maxRequests: 5,
      store: throwingStore,
      degradedModePolicy: 'fail_closed',
    });
    const res3 = await invokeLimiterWithContext(throwingLimiter);
    assert.equal(res3.status, 503);
    assert.equal(res3.nextCalled, false, 'Requests must NOT pass through when shared store throws under fail_closed');
    assert.equal(res3.headers['x-ratelimit-protection'], 'fail-closed-unavailable');

    // 6. Explicitly configured memory_fallback behaves as documented and never claims multi-instance protection
    const memoryFallbackLimiter = createBoundedRateLimiter({
      scope: `prod-mem-fallback-${TEST_RUN_ID}`,
      windowMs: 60_000,
      maxRequests: 5,
      store: undefined,
      degradedModePolicy: 'memory_fallback',
    });
    const res4 = await invokeLimiterWithContext(memoryFallbackLimiter);
    assert.equal(res4.status, 200);
    assert.equal(res4.nextCalled, true);
    assert.equal(res4.headers['x-ratelimit-protection'], 'per-instance-only');
    assert.equal(res4.headers['x-ratelimit-degraded-mode'], 'per-instance-memory-fallback');
    assert.notEqual(res4.headers['x-ratelimit-protection'], 'multi-instance-shared');

    // 7. Development and test behavior remains compatible
    const devEnv: NodeJS.ProcessEnv = { NODE_ENV: 'development' };
    const devResolution = resolveRateLimitStoreConfig(devEnv);
    assert.equal(devResolution.type, 'memory_local');
    assert.equal(devResolution.store, undefined);
    assert.equal(devResolution.degradedModePolicy, 'memory_fallback');

    const devLimiter = createBoundedRateLimiter({
      scope: `dev-compat-${TEST_RUN_ID}`,
      windowMs: 60_000,
      maxRequests: 5,
      store: devResolution.store,
      degradedModePolicy: devResolution.degradedModePolicy,
    });
    const res5 = await invokeLimiterWithContext(devLimiter);
    assert.equal(res5.status, 200);
    assert.equal(res5.nextCalled, true);

    // 8. Authentication and password-recovery routes enforce configured fail_closed policy
    const prodNoDbResolution = resolveRateLimitStoreConfig({ NODE_ENV: 'production' });
    assert.equal(prodNoDbResolution.degradedModePolicy, 'fail_closed');

    const testRegisterLimiter = createBoundedRateLimiter({
      scope: 'auth-register',
      maxRequests: 15,
      windowMs: 60_000,
      store: prodNoDbResolution.store,
      degradedModePolicy: prodNoDbResolution.degradedModePolicy,
    });
    const testLoginLimiter = createBoundedRateLimiter({
      scope: 'auth-login',
      maxRequests: 15,
      windowMs: 60_000,
      store: prodNoDbResolution.store,
      degradedModePolicy: prodNoDbResolution.degradedModePolicy,
    });
    const testForgotPasswordLimiter = createBoundedRateLimiter({
      scope: 'auth-forgot-password',
      maxRequests: 6,
      windowMs: 60_000,
      store: prodNoDbResolution.store,
      degradedModePolicy: prodNoDbResolution.degradedModePolicy,
    });
    const testResetPasswordLimiter = createBoundedRateLimiter({
      scope: 'auth-reset-password',
      maxRequests: 10,
      windowMs: 60_000,
      store: prodNoDbResolution.store,
      degradedModePolicy: prodNoDbResolution.degradedModePolicy,
    });
    const testPasswordMutationLimiter = createBoundedRateLimiter({
      scope: 'auth-password-mutation',
      maxRequests: 10,
      windowMs: 60_000,
      store: prodNoDbResolution.store,
      degradedModePolicy: prodNoDbResolution.degradedModePolicy,
    });

    for (const [name, limiter] of [
      ['registerLimiter', testRegisterLimiter],
      ['loginLimiter', testLoginLimiter],
      ['forgotPasswordLimiter', testForgotPasswordLimiter],
      ['resetPasswordLimiter', testResetPasswordLimiter],
      ['passwordMutationLimiter', testPasswordMutationLimiter],
    ] as const) {
      const routeRes = await invokeLimiterWithContext(limiter);
      assert.equal(routeRes.status, 503, `${name} must reject with 503 when production store is absent under fail_closed`);
      assert.equal(routeRes.nextCalled, false, `${name} must not allow request through`);
      assert.equal(routeRes.headers['x-ratelimit-protection'], 'fail-closed-unavailable');
    }
  });

  it('F2. Resolves authoritative provider identities without UID prefix guessing across local, Firebase, linked, and arbitrary non-prefix UIDs', async () => {
    // 1. Pure unit test for resolveUserFirebaseUid across all UID formats
    // Standard local UID
    assert.equal(
      resolveUserFirebaseUid({ uid: 'usr_abc123', authProvider: 'local', firebaseUid: null }),
      null
    );
    // Arbitrary non-standard local UID (UUID, custom format, student number - does NOT start with usr_)
    assert.equal(
      resolveUserFirebaseUid({ uid: 'c7a4b8-uuid-local-999', authProvider: 'local', firebaseUid: null }),
      null,
      'Must NOT treat arbitrary local UID as Firebase UID'
    );
    // Local account with shadow Firebase identity
    assert.equal(
      resolveUserFirebaseUid({ uid: 'c7a4b8-uuid-local-999', authProvider: 'local', firebaseUid: 'fb_shadow_456' }),
      'fb_shadow_456'
    );
    // Firebase account with standard Firebase UID
    assert.equal(
      resolveUserFirebaseUid({ uid: 'fb_standard_uid', authProvider: 'firebase', firebaseUid: null }),
      'fb_standard_uid'
    );
    // Firebase account whose UID happens to start with usr_ (e.g. custom or migrated UID)
    assert.equal(
      resolveUserFirebaseUid({ uid: 'usr_firebase_custom_id', authProvider: 'firebase', firebaseUid: null }),
      'usr_firebase_custom_id',
      'Must recognize Firebase account even if UID begins with usr_'
    );
    // Linked account
    assert.equal(
      resolveUserFirebaseUid({ uid: 'usr_linked_123', authProvider: 'both', firebaseUid: 'fb_linked_789' }),
      'fb_linked_789'
    );

    // 2. Database integration test: Non-standard local UID (uuid-format without usr_ prefix)
    const suffix = crypto.randomBytes(4).toString('hex');
    const nonPrefixLocalUid = `uuid_local_${suffix}`;
    const nonPrefixEmail = `nonprefix.local.${suffix}@test.medatlas.internal`;
    const initialPassword = 'Password123!Valid';
    const initialHash = await hashPasswordAsync(initialPassword);

    await db.insert(users).values({
      uid: nonPrefixLocalUid,
      email: nonPrefixEmail,
      displayName: 'Non Prefix Student',
      passwordHash: initialHash,
      authProvider: 'local',
      firebaseUid: null,
      accountStatus: 'active',
      role: 'student',
      tokenVersion: 1,
    });

    let fbUpdateInvoked = false;
    setFirebasePasswordUpdateHandlerForTests(async () => {
      fbUpdateInvoked = true;
      return true;
    });

    try {
      // Password change for non-prefix local account MUST NOT invoke Firebase sync
      await changeAuthenticatedUserPassword(nonPrefixLocalUid, initialPassword, 'NewPassword123!Valid');
      assert.equal(fbUpdateInvoked, false, 'Local account without Firebase UID must not invoke Firebase password sync');

      // Account deletion for non-prefix local account MUST report status 'not_applicable', not 'pending_retry'
      await deleteUserAccount(nonPrefixLocalUid);
      const [tombstone] = await db
        .select()
        .from(deletedAccounts)
        .where(eq(deletedAccounts.uid, nonPrefixLocalUid));
      assert.ok(tombstone, 'Tombstone must be recorded');
      assert.equal(
        tombstone.remoteCleanupStatus,
        'not_applicable',
        'Local account deletion must be not_applicable, not pending_retry'
      );
      assert.equal(tombstone.firebaseUid, null);
    } finally {
      setFirebasePasswordUpdateHandlerForTests(null);
      await db.delete(users).where(eq(users.uid, nonPrefixLocalUid)).catch(() => {});
      await db.delete(deletedAccounts).where(eq(deletedAccounts.uid, nonPrefixLocalUid)).catch(() => {});
    }
  });

  it('F3. Password changes are resilient to partial failure: handles provider success followed by DB failure via compensating rollback or defensive invalidation, provider failure, and successful synchronization', async () => {
    const suffix = crypto.randomBytes(4).toString('hex');
    const testEmail = `f3.resilience.${suffix}@test.medatlas.internal`;
    const userUid = `usr_f3_${suffix}`;
    const fbUid = `fb_f3_${suffix}`;
    const oldPassword = 'OldPassword123!A';
    const newPassword = 'NewPassword123!B';
    const oldHash = await hashPasswordAsync(oldPassword);

    await db.insert(users).values({
      uid: userUid,
      firebaseUid: fbUid,
      email: testEmail,
      displayName: 'Resilience Test User',
      passwordHash: oldHash,
      authProvider: 'both',
      accountStatus: 'active',
      role: 'student',
      tokenVersion: 1,
      passwordUpdatedAt: new Date(),
    });

    try {
      // Case 3.1: Provider failure (Firebase rejects password update)
      // Must abort cleanly without modifying PostgreSQL
      setFirebasePasswordUpdateHandlerForTests(async (params) => {
        if (params.newPassword === newPassword) {
          return false; // Provider failure
        }
        return true;
      });

      await assert.rejects(
        async () => changeAuthenticatedUserPassword(userUid, oldPassword, newPassword),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 503
      );

      // Verify old password still works and new password does not
      const authOldAfterProviderFail = await authenticateEmailUser(testEmail, oldPassword);
      assert.ok(authOldAfterProviderFail, 'Old password must still authenticate after provider failure');
      const authNewAfterProviderFail = await authenticateEmailUser(testEmail, newPassword);
      assert.equal(authNewAfterProviderFail, null, 'New password must not authenticate after provider failure');

      // Case 3.2: Partial failure: Provider succeeds, then PostgreSQL update fails, with compensating rollback
      let providerPasswordState = oldPassword;
      let rollbackInvoked = false;

      setFirebasePasswordUpdateHandlerForTests(async (params) => {
        if (params.newPassword === newPassword) {
          providerPasswordState = newPassword; // Provider updated to new password
          return true;
        }
        if (params.newPassword === oldPassword) {
          providerPasswordState = oldPassword; // Compensating rollback back to old password
          rollbackInvoked = true;
          return true;
        }
        return true;
      });

      // Inject DB failure after provider sync
      setSimulateDbFailureAfterProviderSyncForTests(async () => {
        throw new Error('Simulated DB connection failure after provider sync');
      });

      await assert.rejects(
        async () => changeAuthenticatedUserPassword(userUid, oldPassword, newPassword),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 500
      );

      assert.equal(rollbackInvoked, true, 'Compensating rollback to Firebase must be invoked on DB failure');
      assert.equal(providerPasswordState, oldPassword, 'Provider password must be reverted to old password');

      // Case 3.3: Partial failure when compensating rollback cannot be completed:
      // Must defensively invalidate local password and revoke sessions so old password cannot authenticate
      setSimulateDbFailureAfterProviderSyncForTests(async () => {
        throw new Error('Simulated DB failure after provider sync');
      });

      setFirebasePasswordUpdateHandlerForTests(async (params) => {
        if (params.newPassword === newPassword) {
          providerPasswordState = newPassword;
          return true;
        }
        if (params.newPassword === oldPassword) {
          return false; // Revert failed!
        }
        return true;
      });

      await assert.rejects(
        async () => changeAuthenticatedUserPassword(userUid, oldPassword, newPassword),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 500
      );

      // Verify defensive invalidation: local password was invalidated
      const [userAfterDefensiveInval] = await db
        .select()
        .from(users)
        .where(eq(users.uid, userUid));
      assert.equal(
        userAfterDefensiveInval.passwordHash,
        null,
        'Local password hash must be invalidated so old password can NEVER authenticate'
      );
      assert.ok(userAfterDefensiveInval.pendingRecoveryAt !== null, 'pendingRecoveryAt must be active for reconciliation');

      // Verify old password cannot authenticate
      const authOldAfterDefensive = await authenticateEmailUser(testEmail, oldPassword);
      assert.equal(authOldAfterDefensive, null, 'Old password must NOT authenticate');

      // Now verify new password reconciles through authenticateEmailUser
      setFirebasePasswordVerifyHandlerForTests(async (email, pwd) => {
        if (email.toLowerCase().trim() === testEmail.toLowerCase().trim() && pwd === newPassword) {
          return { valid: true, firebaseUid: fbUid };
        }
        return { valid: false, definiteRejection: true };
      });

      const reconciledUser = await authenticateEmailUser(testEmail, newPassword);
      assert.ok(reconciledUser, 'New password must reconcile and authenticate successfully');

      // Case 3.4: Successful synchronization (both provider and DB succeed)
      setSimulateDbFailureAfterProviderSyncForTests(null);
      const newestPassword = 'NewestPassword123!C';
      setFirebasePasswordUpdateHandlerForTests(async () => true);

      const changeSuccess = await changeAuthenticatedUserPassword(userUid, newPassword, newestPassword);
      assert.ok(changeSuccess, 'Password change must succeed when both provider and DB succeed');

      // Old password must fail, newest password must work
      const authPrev = await authenticateEmailUser(testEmail, newPassword);
      assert.equal(authPrev, null, 'Previous password must not authenticate after successful change');
      const authCurrent = await authenticateEmailUser(testEmail, newestPassword);
      assert.ok(authCurrent, 'Newest password must authenticate after successful change');
    } finally {
      setFirebasePasswordUpdateHandlerForTests(null);
      setFirebasePasswordVerifyHandlerForTests(null);
      setSimulateDbFailureAfterProviderSyncForTests(null);
      await db.delete(users).where(eq(users.uid, userUid)).catch(() => {});
    }
  });

  it('F4. Database-token password recovery enforces Firebase synchronization with requireSuccess: true, prevents inconsistent credentials, and rejects localEmailTransport in production', async () => {
    // 1. localEmailTransport is strictly rejected in production
    const prodEmail = `prod.transport.${TEST_RUN_ID}@medatlas.test`;
    const prodUser = await registerEmailPasswordUser(prodEmail, 'Pass123!Secure', 'Prod User');
    createdUserUids.push(prodUser.uid);

    const prevEnv = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      await assert.rejects(
        async () =>
          requestPasswordRecoveryToken(prodEmail, {
            localEmailTransport: async () => {},
          }),
        (err: any) =>
          err instanceof ClientSafeError &&
          err.statusCode === 400 &&
          /forbidden in production/i.test(err.message)
      );
    } finally {
      process.env.NODE_ENV = prevEnv;
    }

    // 2. Database-token reset for an account linked to Firebase:
    // If Firebase synchronization fails, it MUST fail closed (503), NOT consume the token, and NOT modify PostgreSQL!
    const suffix = crypto.randomBytes(4).toString('hex');
    const linkedEmail = `f4.recovery.${suffix}@test.medatlas.internal`;
    const linkedUserUid = `usr_f4_${suffix}`;
    const linkedFbUid = `fb_f4_${suffix}`;
    const initialPass = 'InitialLinkedPass123!';
    const initialHash = await hashPasswordAsync(initialPass);

    await db.insert(users).values({
      uid: linkedUserUid,
      firebaseUid: linkedFbUid,
      email: linkedEmail,
      displayName: 'F4 Linked Student',
      passwordHash: initialHash,
      authProvider: 'both',
      accountStatus: 'active',
      role: 'student',
      tokenVersion: 1,
      passwordUpdatedAt: new Date(),
    });

    const recoveryRawToken = crypto.randomBytes(32).toString('hex');
    const recoveryTokenHash = hashRecoveryToken(recoveryRawToken);
    const [insertedToken] = await db
      .insert(passwordResetTokens)
      .values({
        userUid: linkedUserUid,
        tokenHash: recoveryTokenHash,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      })
      .returning();

    const attemptedNewPass = 'AttemptedNewPass456!';

    // Simulate Firebase provider update failure
    setFirebasePasswordUpdateHandlerForTests(async () => false);

    try {
      await assert.rejects(
        async () => confirmPasswordRecoveryToken(recoveryRawToken, attemptedNewPass),
        (err: any) => err instanceof ClientSafeError && err.statusCode === 503
      );

      // Verify token was NOT consumed
      const [tokenAfterFail] = await db
        .select()
        .from(passwordResetTokens)
        .where(eq(passwordResetTokens.id, insertedToken.id));
      assert.equal(tokenAfterFail.consumedAt, null, 'Token must NOT be consumed when provider sync fails');

      // Verify PostgreSQL credentials were NOT modified
      const [userAfterFail] = await db
        .select()
        .from(users)
        .where(eq(users.uid, linkedUserUid));
      assert.equal(userAfterFail.tokenVersion, 1);
      assert.equal(verifyPassword(initialPass, userAfterFail.passwordHash!), true);
      assert.equal(verifyPassword(attemptedNewPass, userAfterFail.passwordHash!), false);

      // Now simulate Firebase provider update SUCCESS
      setFirebasePasswordUpdateHandlerForTests(async (params) => {
        return params.newPassword === attemptedNewPass;
      });

      const resetResult = await confirmPasswordRecoveryToken(recoveryRawToken, attemptedNewPass);
      assert.ok(resetResult);
      assert.equal(resetResult.tokenVersion, 2);

      // Token IS consumed now
      const [tokenAfterSuccess] = await db
        .select()
        .from(passwordResetTokens)
        .where(eq(passwordResetTokens.id, insertedToken.id));
      assert.ok(tokenAfterSuccess.consumedAt !== null, 'Token must be consumed on successful reset');

      // Credentials are fully synchronized
      const [userAfterSuccess] = await db
        .select()
        .from(users)
        .where(eq(users.uid, linkedUserUid));
      assert.equal(verifyPassword(initialPass, userAfterSuccess.passwordHash!), false);
      assert.equal(verifyPassword(attemptedNewPass, userAfterSuccess.passwordHash!), true);
    } finally {
      setFirebasePasswordUpdateHandlerForTests(null);
      await db.delete(passwordResetTokens).where(eq(passwordResetTokens.userUid, linkedUserUid)).catch(() => {});
      await db.delete(users).where(eq(users.uid, linkedUserUid)).catch(() => {});
    }
  });
});


