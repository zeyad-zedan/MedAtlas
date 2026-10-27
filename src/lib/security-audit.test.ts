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
  type AuthRequest,
} from '../middleware/auth.ts';
import { createBoundedRateLimiter } from '../middleware/rate-limit.ts';
import { sanitizeSvgDiagram } from './mcq-engine.ts';
import {
  ClientSafeError,
  evaluateServerExamDeadline,
  registerEmailPasswordUser,
  findUserByEmail,
  getOrCreateUser,
  dispatchFirebasePasswordResetEmail,
  requestPasswordRecoveryToken,
  confirmPasswordRecoveryToken,
  linkPasswordToAuthenticatedAccount,
  deleteUserAccount,
  saveSessionQuestionAnswer,
  completeExamSession,
} from '../db/repository.ts';
import { db, pool } from '../db/index.ts';
import {
  users,
  passwordResetTokens,
  deletedAccounts,
  subjects,
  lectures,
  questions,
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
  // 1 & 2. CRITICAL: PASSWORD RESET & RECOVERY TOKEN SECURITY
  // ==========================================================================
  it('1. Rejects unauthenticated password reset attempts that lack a valid recovery token', async () => {
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

  it('2. Enforces hashed, single-use, expiring recovery tokens and invalidates prior sessions upon reset', async () => {
    const email = `sec.reset.${TEST_RUN_ID}@medatlas.test`;
    const user = await registerEmailPasswordUser(
      email,
      'InitialSecurePass123!',
      'Reset Test Student'
    );
    createdUserUids.push(user.uid);

    // Issue a session token at initial tokenVersion (1)
    const oldSessionToken = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
      tokenVersion: user.tokenVersion,
    });

    // Request token #1, then immediately request token #2 (which must supersede token #1)
    const req1 = await requestPasswordRecoveryToken(email, {
      returnTokenForTesting: true,
    });
    const req2 = await requestPasswordRecoveryToken(email, {
      returnTokenForTesting: true,
    });

    assert.ok(req1._testRecoveryToken && req1._testRecoveryToken.length === 64);
    assert.ok(req2._testRecoveryToken && req2._testRecoveryToken.length === 64);
    assert.notEqual(req1._testRecoveryToken, req2._testRecoveryToken);

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

    // Firebase Auth password-reset email dispatch works directly via configured Firebase project without PASSWORD_RESET_WEBHOOK_URL
    const firebaseDispatched = await dispatchFirebasePasswordResetEmail(email);
    assert.equal(firebaseDispatched, true);
  });

  // ==========================================================================
  // 3, 4 & 5. CRITICAL: SESSION SECRET & TOKEN VERIFICATION
  // ==========================================================================
  it('3. Rejects missing, short, low-entropy, or placeholder AUTH_SESSION_SECRET values', () => {
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
  });

  it('4 & 5. Rejects forged tokens signed with old hardcoded secret and expired tokens', () => {
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

    // Provision a provider-authenticated user (passwordHash is null)
    const createdProviderUser = await getOrCreateUser(
      providerUid,
      providerEmail,
      'Dr. Provider Student',
      { authType: 'firebase', emailVerified: true, allowCreate: true }
    );
    assert.equal(createdProviderUser.uid, providerUid);
    assert.equal(createdProviderUser.passwordHash, null);

    // Attacker attempts to register via /api/auth/register using the victim's email
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

    // Verify victim's passwordHash is STILL null and UID is unchanged
    const [victimAfterAttack] = await db
      .select()
      .from(users)
      .where(eq(users.uid, providerUid));
    assert.equal(victimAfterAttack.passwordHash, null);
    assert.equal(victimAfterAttack.displayName, 'Dr. Provider Student');

    // Unverified Firebase email token must be rejected from provisioning/linking
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

    // Conflicting UID for an existing email must NOT overwrite the existing user's UID
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

    // Authenticated owner can explicitly link a local password via linkPasswordToAuthenticatedAccount
    const linked = await linkPasswordToAuthenticatedAccount(
      providerUid,
      'OwnerLinkedPassword123!'
    );
    assert.ok(linked.passwordHash && linked.passwordHash.length > 0);
    assert.equal(linked.authProvider, 'both');
  });

  // ==========================================================================
  // 8 & 9. HIGH: SERVER-SIDE EXAM DEADLINES & ATOMIC RACE-SAFE COMPLETION
  // ==========================================================================
  it('8 & 9. Enforces server-side exam deadlines and prevents duplicate question_attempts under concurrent completion', async () => {
    // Pure deadline evaluator unit checks
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

    // Database integration test for exam deadline & concurrent completion
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

    // Create an active exam session that started 10 seconds ago with a 300s limit
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

    // Fire 3 concurrent completion calls with manipulated clientElapsedSeconds = 1
    const [resA, resB, resC] = await Promise.all([
      completeExamSession(examUser.uid, activeExam.id, { [q1.id]: 'B', [q2.id]: 'A' }, 1),
      completeExamSession(examUser.uid, activeExam.id, { [q1.id]: 'B', [q2.id]: 'A' }, 1),
      completeExamSession(examUser.uid, activeExam.id, { [q1.id]: 'B', [q2.id]: 'A' }, 1),
    ]);

    assert.equal(resA.status, 'completed');
    assert.equal(resB.status, 'completed');
    assert.equal(resC.status, 'completed');
    assert.equal(resA.correctCount, 2);
    // Server must compute elapsedSeconds from server startedAt (~10s), NOT client-supplied 1s!
    assert.ok(resA.elapsedSeconds >= 9, `Expected server elapsed >= 9s, got ${resA.elapsedSeconds}`);

    // Verify strictly 2 question_attempts rows exist (zero duplicates despite 3 concurrent calls)
    const attemptsInDb = await db
      .select()
      .from(questionAttempts)
      .where(eq(questionAttempts.sessionId, activeExam.id));
    assert.equal(attemptsInDb.length, 2);

    // Now test expired exam session deadline enforcement
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
        // Started 5 minutes ago on a 1-minute exam
        startedAt: new Date(Date.now() - 300_000),
      })
      .returning();
    createdSessionIds.push(expiredExam.id);

    // Attempting to save an answer after deadline expiration must be rejected with 409
    await assert.rejects(
      async () => {
        await saveSessionQuestionAnswer(
          examUser.uid,
          expiredExam.id,
          q2.id,
          'A',
          false,
          5 // spoofed client elapsedSeconds = 5
        );
      },
      (err: any) =>
        err instanceof ClientSafeError &&
        err.statusCode === 409 &&
        /expired/i.test(err.message)
    );

    // Attempting to mutate answers during late completion past grace window must be rejected with 409
    await assert.rejects(
      async () => {
        await completeExamSession(
          examUser.uid,
          expiredExam.id,
          { [q1.id]: 'B', [q2.id]: 'A' }, // trying to change q2 from null -> 'A' after deadline
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

    // Delete account
    const delResult = await deleteUserAccount(delUser.uid);
    assert.equal(delResult.deleted, true);

    // Calling getOrCreateUser with the deleted UID (even as firebase or local) must fail with 401 and NEVER recreate the user
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

    // Verify user row is still absent from users table
    const remainingUserRows = await db
      .select()
      .from(users)
      .where(eq(users.uid, delUser.uid));
    assert.equal(remainingUserRows.length, 0);

    // Verify requireAuth immediately rejects the token that was issued before deletion
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
  // 11. MEDIUM: BOUNDED SELF-PRUNING RATE LIMITER
  // ==========================================================================
  it('11. Enforces request rate limits, prunes expired entries, and caps memory at maxKeys', () => {
    const limiter = createBoundedRateLimiter({
      scope: 'unit-test-limiter',
      windowMs: 2_000,
      maxRequests: 3,
      maxKeys: 25,
    });

    const makeMockPair = (ip: string) => {
      let statusCode = 200;
      const headers: Record<string, string> = {};
      const req = {
        ip,
        baseUrl: '/api/auth',
        path: '/login',
        socket: { remoteAddress: ip },
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

    // First 3 requests from 10.0.0.1 succeed; 4th is blocked with 429 and Retry-After
    for (let i = 1; i <= 3; i++) {
      const { req, res, getStatus } = makeMockPair('10.0.0.1');
      let nextCalled = false;
      limiter(req, res, () => {
        nextCalled = true;
      });
      assert.equal(nextCalled, true);
      assert.equal(getStatus(), 200);
    }

    const fourth = makeMockPair('10.0.0.1');
    let fourthNext = false;
    limiter(fourth.req, fourth.res, () => {
      fourthNext = true;
    });
    assert.equal(fourthNext, false);
    assert.equal(fourth.getStatus(), 429);
    assert.ok(Number(fourth.headers['Retry-After']) >= 1);

    // Flood with 100 unique spoofed IPs and verify store size never exceeds maxKeys (25)
    for (let i = 0; i < 100; i++) {
      const { req, res } = makeMockPair(`192.168.1.${i}`);
      limiter(req, res, () => {});
      assert.ok(
        limiter.getStoreSize() <= 25,
        `Rate limiter exceeded maxKeys: ${limiter.getStoreSize()}`
      );
    }

    // Prune after window expiration clears all entries
    const removed = limiter.pruneExpired(Date.now() + 10_000);
    assert.equal(removed, 25);
    assert.equal(limiter.getStoreSize(), 0);
  });

  // ==========================================================================
  // 12. BROADER AUDIT: SVG DIAGRAM XSS SANITIZATION
  // ==========================================================================
  it('12. Strips <script>, <foreignObject>, inline event handlers, and javascript: URIs from SVG diagrams', () => {
    const maliciousSvg = `
      <svg viewBox="0 0 100 100" onload="alert('xss')">
        <script>window.stealToken()</script>
        <foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject>
        <a href="javascript:evil()" xlink:href="data:text/html,<script>alert(1)</script>">
          <circle cx="50" cy="50" r="40" onclick="evil()" fill="#0284C7" />
        </a>
      </svg>
    `;
    const clean = sanitizeSvgDiagram(maliciousSvg);
    assert.ok(!/<script/i.test(clean));
    assert.ok(!/<foreignObject/i.test(clean));
    assert.ok(!/<iframe/i.test(clean));
    assert.ok(!/onload\s*=/i.test(clean));
    assert.ok(!/onclick\s*=/i.test(clean));
    assert.ok(!/javascript:/i.test(clean));
    assert.ok(!/data:text\/html/i.test(clean));
    assert.ok(clean.includes('<circle cx="50" cy="50" r="40"'));
  });
});
