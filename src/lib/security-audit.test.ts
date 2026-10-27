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
  hashRecoveryToken,
  requireAuth,
  recordUserSessionRevocation,
  setFirebaseTokenVerifierForTests,
  type AuthRequest,
} from '../middleware/auth.ts';
import {
  createBoundedRateLimiter,
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
  setFirebaseOobHandlerForTests,
  requestPasswordRecoveryToken,
  confirmPasswordRecoveryToken,
  linkPasswordToAuthenticatedAccount,
  revokeUserSessions,
  deleteUserAccount,
  updateUserRoleAdmin,
  toggleBookmarkForStudent,
  saveSessionQuestionAnswer,
  completeExamSession,
  type LocalEmailTransportFn,
} from '../db/repository.ts';
import { db, pool } from '../db/index.ts';
import {
  users,
  passwordResetTokens,
  deletedAccounts,
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
  setFirebaseOobHandlerForTests(null);
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

  it('P2.2 Local-only password reset fails honestly (503) when unconfigured, delivers single-use tokens when configured, and rejects untrusted origins', async () => {
    const email = `sec.reset.${TEST_RUN_ID}@medatlas.test`;
    const user = await registerEmailPasswordUser(
      email,
      'InitialSecurePass123!',
      'Reset Test Student'
    );
    createdUserUids.push(user.uid);

    // 1. When no local email webhook/dispatcher is configured, local-only reset must fail honestly with 503
    const prevWebhook = process.env.LOCAL_PASSWORD_RESET_WEBHOOK_URL;
    const prevLegacyWebhook = process.env.PASSWORD_RESET_WEBHOOK_URL;
    delete process.env.LOCAL_PASSWORD_RESET_WEBHOOK_URL;
    delete process.env.PASSWORD_RESET_WEBHOOK_URL;

    try {
      await assert.rejects(
        async () => {
          await requestPasswordRecoveryToken(email, {
            enforceDeliveryConfigInTest: true,
          });
        },
        (err: any) =>
          err instanceof ClientSafeError &&
          err.statusCode === 503 &&
          /LOCAL_PASSWORD_RESET_WEBHOOK_URL/i.test(err.message)
      );
    } finally {
      if (prevWebhook !== undefined) process.env.LOCAL_PASSWORD_RESET_WEBHOOK_URL = prevWebhook;
      if (prevLegacyWebhook !== undefined)
        process.env.PASSWORD_RESET_WEBHOOK_URL = prevLegacyWebhook;
    }

    // 2. Untrusted recovery origin must be rejected with 400
    await assert.rejects(
      async () => {
        validateTrustedRecoveryOrigin('https://evil-phishing.example.com');
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 400 &&
        /untrusted/i.test(err.message)
    );

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
  it('P6. Enforces request rate limits, ignores spoofed X-Forwarded-For headers, prunes expired entries, and caps memory at maxKeys', () => {
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

    const makeMockPair = (socketIp: string, spoofedXff?: string) => {
      let statusCode = 200;
      const headers: Record<string, string> = {};
      const req = {
        ip: socketIp,
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
      limiter(req, res, () => {
        nextCalled = true;
      });
      assert.equal(nextCalled, true);
      assert.equal(getStatus(), 200);
    }

    // 4th request from 10.0.0.1 with a brand-new spoofed X-Forwarded-For MUST still be blocked (429)
    const fourth = makeMockPair('10.0.0.1', '198.51.100.250');
    let fourthNext = false;
    limiter(fourth.req, fourth.res, () => {
      fourthNext = true;
    });
    assert.equal(fourthNext, false);
    assert.equal(fourth.getStatus(), 429);
    assert.ok(Number(fourth.headers['Retry-After']) >= 1);

    for (let i = 0; i < 100; i++) {
      const { req, res } = makeMockPair(`192.168.1.${i}`);
      limiter(req, res, () => {});
      assert.ok(
        limiter.getStoreSize() <= 25,
        `Rate limiter exceeded maxKeys: ${limiter.getStoreSize()}`
      );
    }

    const removed = limiter.pruneExpired(Date.now() + 10_000);
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
});
