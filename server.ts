import express, { type Request, type Response, type NextFunction } from 'express';
import path from 'node:path';
import * as dotenv from 'dotenv';
import {
  requireAuth,
  type AuthRequest,
  verifyPassword,
  createServerSessionToken,
  validateAuthConfiguration,
} from './src/middleware/auth.ts';
import {
  createBoundedRateLimiter,
  normalizeClientIp,
} from './src/middleware/rate-limit.ts';
import {
  ClientSafeError,
  sanitizeUserForClient,
  getAuthenticatedUserByUid,
  getOrCreateUser,
  registerEmailPasswordUser,
  findUserByEmail,
  requestPasswordRecoveryToken,
  confirmPasswordRecoveryToken,
  changeAuthenticatedUserPassword,
  linkPasswordToAuthenticatedAccount,
  revokeUserSessions,
  updateUserProfile,
  deleteUserAccount,
  getPublishedCatalog,
  createPracticeOrExamSession,
  getExamSessionForStudent,
  saveSessionQuestionAnswer,
  completeExamSession,
  toggleBookmarkForStudent,
  getStudentBookmarksAndReview,
  getStudentDashboardAnalytics,
  getAdminDashboardData,
  upsertSubjectAdmin,
  upsertLectureAdmin,
  upsertQuestionAdmin,
  deleteSubjectAdmin,
  deleteLectureAdmin,
  deleteQuestionBankAdmin,
  deleteOrArchiveQuestionAdmin,
  deleteExamSessionAdmin,
  updateUserRoleAdmin,
  deleteUserAdmin,
  previewCsvImportAdmin,
  executeCsvImportAdmin,
  exportQuestionBankCsvAdmin,
} from './src/db/repository.ts';
import { getSampleCsvTemplate } from './src/lib/mcq-engine.ts';

dotenv.config({ override: true });

// Validate AUTH_SESSION_SECRET at module load / startup (fails fast if missing or weak)
validateAuthConfiguration();

export const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// Security headers middleware
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()'
  );
  next();
});

app.use(express.json({ limit: '5mb' }));

// Bounded, self-pruning rate limiters for authentication and sensitive mutations
const registerLimiter = createBoundedRateLimiter({
  scope: 'auth-register',
  maxRequests: 15,
  windowMs: 60_000,
  maxKeys: 5_000,
});

const loginLimiter = createBoundedRateLimiter({
  scope: 'auth-login',
  maxRequests: 20,
  windowMs: 60_000,
  maxKeys: 5_000,
  keyGenerator: (req) => {
    const email =
      typeof req.body?.email === 'string'
        ? req.body.email.toLowerCase().trim().slice(0, 80)
        : '';
    return `${normalizeClientIp(req)}:${email}`;
  },
});

const forgotPasswordLimiter = createBoundedRateLimiter({
  scope: 'auth-forgot-password',
  maxRequests: 6,
  windowMs: 60_000,
  maxKeys: 5_000,
  keyGenerator: (req) => {
    const email =
      typeof req.body?.email === 'string'
        ? req.body.email.toLowerCase().trim().slice(0, 80)
        : '';
    return `${normalizeClientIp(req)}:${email}`;
  },
});

const resetPasswordLimiter = createBoundedRateLimiter({
  scope: 'auth-reset-password',
  maxRequests: 10,
  windowMs: 60_000,
  maxKeys: 5_000,
});

const passwordMutationLimiter = createBoundedRateLimiter({
  scope: 'auth-password-mutation',
  maxRequests: 10,
  windowMs: 60_000,
  maxKeys: 5_000,
});

function sendErrorResponse(
  res: Response,
  error: unknown,
  fallbackMessage: string,
  defaultStatus = 500
) {
  if (error instanceof ClientSafeError) {
    return res.status(error.statusCode).json({ error: error.message });
  }
  return res.status(defaultStatus).json({ error: fallbackMessage });
}

// Middleware to verify database-backed Administrator role without creating or resurrecting users
const requireAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const dbUser =
      req.user.authType === 'firebase'
        ? await getOrCreateUser(req.user.uid, req.user.email, req.user.name, {
            authType: 'firebase',
            emailVerified: req.user.emailVerified,
            allowCreate: true,
          })
        : await getAuthenticatedUserByUid(req.user.uid);

    if (!dbUser || dbUser.role !== 'admin') {
      return res
        .status(403)
        .json({ error: 'Forbidden: Administrator privileges are required.' });
    }
    return next();
  } catch (error) {
    console.error('Admin verification failed:', error);
    return sendErrorResponse(
      res,
      error,
      'Failed to verify administrator permissions.',
      500
    );
  }
};

// ============================================================================
// PUBLIC CATALOG API
// ============================================================================
app.get('/api/catalog', async (_req, res) => {
  try {
    const catalog = await getPublishedCatalog();
    return res.json(catalog);
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to load catalog.', 500);
  }
});

// ============================================================================
// AUTHENTICATION & ACCOUNT API
// ============================================================================
app.post('/api/auth/register', registerLimiter, async (req, res) => {
  try {
    const { email, password, displayName } = req.body || {};
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    if (!password || typeof password !== 'string' || password.length < 8) {
      return res
        .status(400)
        .json({ error: 'Password must be at least 8 characters long.' });
    }
    if (!displayName || typeof displayName !== 'string' || displayName.trim().length < 2) {
      return res.status(400).json({
        error: 'Please enter your full name or display name (at least 2 characters).',
      });
    }

    const user = await registerEmailPasswordUser(email, password, displayName);
    const token = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
      tokenVersion: user.tokenVersion,
    });

    return res.status(201).json({
      token,
      user: sanitizeUserForClient(user),
    });
  } catch (error) {
    return sendErrorResponse(res, error, 'Registration failed.', 400);
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await findUserByEmail(String(email));
    if (!user || !user.passwordHash || !verifyPassword(String(password), user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid email address or password.' });
    }

    const token = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
      tokenVersion: user.tokenVersion,
    });

    return res.json({
      token,
      user: sanitizeUserForClient(user),
    });
  } catch (error) {
    return sendErrorResponse(res, error, 'Login failed.', 500);
  }
});

/**
 * Step 1 of Password Recovery: Request a single-use cryptographic recovery token.
 * Enumeration-safe: returns the same generic response whether or not the email exists.
 */
app.post('/api/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res
        .status(400)
        .json({ error: 'Please enter a valid account email address.' });
    }
    const result = await requestPasswordRecoveryToken(email);
    return res.json({
      accepted: result.accepted,
      message: result.message,
      expiresInMinutes: result.expiresInMinutes,
    });
  } catch (error) {
    return sendErrorResponse(
      res,
      error,
      'Failed to initiate password recovery.',
      400
    );
  }
});

/**
 * Step 2 of Password Recovery: Complete password reset using a verified single-use recovery token
 * or a Firebase Authentication password-reset oobCode.
 * Unauthenticated reset by { email, newPassword } alone is strictly rejected.
 */
app.post('/api/auth/reset-password', resetPasswordLimiter, async (req, res) => {
  try {
    const { token, oobCode, newPassword } = req.body || {};
    const recoverySecret =
      typeof token === 'string' && token.trim().length > 0
        ? token.trim()
        : typeof oobCode === 'string' && oobCode.trim().length > 0
        ? oobCode.trim()
        : '';

    if (!recoverySecret || recoverySecret.length < 20) {
      return res.status(400).json({
        error:
          'A valid single-use password recovery token or Firebase reset code is required to reset a password.',
      });
    }
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return res
        .status(400)
        .json({ error: 'New password must be at least 8 characters long.' });
    }

    await confirmPasswordRecoveryToken(recoverySecret, newPassword);
    return res.json({
      message:
        'Your password has been updated and prior sessions have been revoked. You may now sign in with your new password.',
    });
  } catch (error) {
    return sendErrorResponse(res, error, 'Password recovery failed.', 400);
  }
});

/**
 * Authenticated password change (requires currentPassword).
 */
app.post(
  '/api/auth/change-password',
  requireAuth,
  passwordMutationLimiter,
  async (req: AuthRequest, res) => {
    try {
      const { currentPassword, newPassword } = req.body || {};
      const updated = await changeAuthenticatedUserPassword(
        req.user!.uid,
        String(currentPassword || ''),
        String(newPassword || '')
      );
      const token = createServerSessionToken({
        uid: updated.uid,
        email: updated.email,
        name: updated.displayName,
        tokenVersion: updated.tokenVersion,
      });
      return res.json({
        message: 'Your password has been updated.',
        token,
        user: sanitizeUserForClient(updated),
      });
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to change password.', 400);
    }
  }
);

/**
 * Authenticated password linking for accounts created via verified OAuth/Firebase provider.
 */
app.post(
  '/api/auth/link-password',
  requireAuth,
  passwordMutationLimiter,
  async (req: AuthRequest, res) => {
    try {
      const { newPassword } = req.body || {};
      const updated = await linkPasswordToAuthenticatedAccount(
        req.user!.uid,
        String(newPassword || '')
      );
      const token = createServerSessionToken({
        uid: updated.uid,
        email: updated.email,
        name: updated.displayName,
        tokenVersion: updated.tokenVersion,
      });
      return res.json({
        message: 'Local password has been linked to your account.',
        token,
        user: sanitizeUserForClient(updated),
      });
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to link password.', 400);
    }
  }
);

app.post('/api/auth/logout', requireAuth, async (req: AuthRequest, res) => {
  try {
    await revokeUserSessions(req.user!.uid);
    return res.json({ loggedOut: true });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to revoke session.', 500);
  }
});

app.get('/api/auth/me', requireAuth, async (req: AuthRequest, res) => {
  try {
    const user = await getOrCreateUser(
      req.user!.uid,
      req.user!.email,
      req.user!.name,
      {
        authType: req.user!.authType,
        emailVerified: req.user!.emailVerified,
        allowCreate: req.user!.authType === 'firebase',
      }
    );
    return res.json({ user: sanitizeUserForClient(user) });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to load profile.', 500);
  }
});

app.put('/api/auth/profile', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { displayName, preferences } = req.body || {};
    if (displayName !== undefined && String(displayName).trim().length < 2) {
      return res
        .status(400)
        .json({ error: 'Display name must be at least 2 characters long.' });
    }
    const updated = await updateUserProfile(req.user!.uid, {
      displayName: displayName ? String(displayName) : undefined,
      preferences: typeof preferences === 'object' ? preferences : undefined,
    });
    return res.json({ user: sanitizeUserForClient(updated) });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to update profile.', 500);
  }
});

app.delete('/api/auth/account', requireAuth, async (req: AuthRequest, res) => {
  try {
    const result = await deleteUserAccount(req.user!.uid);
    return res.json(result);
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to delete account.', 500);
  }
});

// ============================================================================
// STUDENT MCQ SESSIONS, BOOKMARKS & DASHBOARD ANALYTICS
// ============================================================================
app.post('/api/sessions', requireAuth, async (req: AuthRequest, res) => {
  try {
    const {
      mode,
      title,
      subjectIds,
      lectureIds,
      difficulties,
      tagFilter,
      requestedCount,
      shuffleQuestions,
      shuffleOptions,
      avoidRecent,
      timeLimitMinutes,
    } = req.body || {};

    const validMode = mode === 'exam' || mode === 'custom' ? mode : 'study';
    const result = await createPracticeOrExamSession(req.user!.uid, {
      mode: validMode,
      title,
      subjectIds: Array.isArray(subjectIds) ? subjectIds.map(Number) : undefined,
      lectureIds: Array.isArray(lectureIds) ? lectureIds.map(Number) : undefined,
      difficulties: Array.isArray(difficulties) ? difficulties : undefined,
      tagFilter: tagFilter ? String(tagFilter) : undefined,
      requestedCount: requestedCount ? Number(requestedCount) : undefined,
      shuffleQuestions: Boolean(shuffleQuestions),
      shuffleOptions: Boolean(shuffleOptions),
      avoidRecent: Boolean(avoidRecent),
      timeLimitMinutes:
        timeLimitMinutes !== undefined && timeLimitMinutes !== null
          ? Number(timeLimitMinutes)
          : undefined,
    });
    return res.status(201).json(result);
  } catch (error) {
    return sendErrorResponse(res, error, 'Could not start session.', 400);
  }
});

app.get('/api/sessions/:id', requireAuth, async (req: AuthRequest, res) => {
  try {
    const sessionId = Number(req.params.id);
    if (!Number.isInteger(sessionId) || sessionId <= 0) {
      return res.status(400).json({ error: 'Invalid session ID.' });
    }
    const session = await getExamSessionForStudent(req.user!.uid, sessionId);
    return res.json({ session });
  } catch (error) {
    return sendErrorResponse(res, error, 'Session not found.', 404);
  }
});

app.post('/api/sessions/:id/answer', requireAuth, async (req: AuthRequest, res) => {
  try {
    const sessionId = Number(req.params.id);
    if (!Number.isInteger(sessionId) || sessionId <= 0) {
      return res.status(400).json({ error: 'Invalid session ID.' });
    }
    const { questionId, selectedOption, lockAnswer, elapsedSeconds } = req.body || {};
    const session = await saveSessionQuestionAnswer(
      req.user!.uid,
      sessionId,
      Number(questionId),
      selectedOption || null,
      Boolean(lockAnswer),
      typeof elapsedSeconds === 'number' ? elapsedSeconds : undefined
    );
    return res.json({ session });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to record answer.', 400);
  }
});

app.post('/api/sessions/:id/complete', requireAuth, async (req: AuthRequest, res) => {
  try {
    const sessionId = Number(req.params.id);
    if (!Number.isInteger(sessionId) || sessionId <= 0) {
      return res.status(400).json({ error: 'Invalid session ID.' });
    }
    const { answers, elapsedSeconds } = req.body || {};
    const session = await completeExamSession(
      req.user!.uid,
      sessionId,
      answers,
      typeof elapsedSeconds === 'number' ? elapsedSeconds : undefined
    );
    return res.json({ session });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to complete session.', 400);
  }
});

app.get('/api/dashboard', requireAuth, async (req: AuthRequest, res) => {
  try {
    const analytics = await getStudentDashboardAnalytics(req.user!.uid);
    return res.json(analytics);
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to load dashboard.', 500);
  }
});

app.get('/api/bookmarks', requireAuth, async (req: AuthRequest, res) => {
  try {
    const data = await getStudentBookmarksAndReview(req.user!.uid);
    return res.json(data);
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to load bookmarks.', 500);
  }
});

app.post('/api/bookmarks/toggle', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { questionId, note } = req.body || {};
    if (!questionId) {
      return res.status(400).json({ error: 'questionId is required.' });
    }
    const result = await toggleBookmarkForStudent(
      req.user!.uid,
      Number(questionId),
      note ? String(note) : undefined
    );
    return res.json(result);
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to toggle bookmark.', 500);
  }
});

// ============================================================================
// PROTECTED ADMINISTRATOR API
// ============================================================================
app.get('/api/admin/overview', requireAuth, requireAdmin, async (_req: AuthRequest, res) => {
  try {
    const data = await getAdminDashboardData();
    return res.json(data);
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to load admin overview.', 500);
  }
});

app.post('/api/admin/subjects', requireAuth, requireAdmin, async (req: AuthRequest, res) => {
  try {
    const { id, title, description, displayOrder, status } = req.body || {};
    if (!title || !description) {
      return res.status(400).json({ error: 'Subject title and description are required.' });
    }
    const saved = await upsertSubjectAdmin(
      { uid: req.user!.uid, email: req.user!.email },
      {
        id: id ? Number(id) : undefined,
        title: String(title),
        description: String(description),
        displayOrder: Number(displayOrder) || 1,
        status: status || 'published',
      }
    );
    return res.json({ subject: saved });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to save subject.', 400);
  }
});

app.post('/api/admin/lectures', requireAuth, requireAdmin, async (req: AuthRequest, res) => {
  try {
    const {
      id,
      subjectId,
      title,
      description,
      lectureNumber,
      educationalNotes,
      estimatedMinutes,
      status,
    } = req.body || {};
    if (!subjectId || !title || !description) {
      return res
        .status(400)
        .json({ error: 'Parent subject, lecture title, and description are required.' });
    }
    const saved = await upsertLectureAdmin(
      { uid: req.user!.uid, email: req.user!.email },
      {
        id: id ? Number(id) : undefined,
        subjectId: Number(subjectId),
        title: String(title),
        description: String(description),
        lectureNumber: Number(lectureNumber) || 1,
        educationalNotes: educationalNotes ? String(educationalNotes) : '',
        estimatedMinutes: Number(estimatedMinutes) || 30,
        status: status || 'published',
      }
    );
    return res.json({ lecture: saved });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to save lecture.', 400);
  }
});

app.post('/api/admin/questions', requireAuth, requireAdmin, async (req: AuthRequest, res) => {
  try {
    const {
      id,
      subjectId,
      lectureId,
      questionText,
      optionA,
      optionB,
      optionC,
      optionD,
      correctAnswer,
      explanation,
      explanationA,
      explanationB,
      explanationC,
      explanationD,
      difficulty,
      tags,
      status,
    } = req.body || {};

    if (
      !subjectId ||
      !lectureId ||
      !questionText ||
      !optionA ||
      !optionB ||
      !optionC ||
      !optionD ||
      !correctAnswer ||
      !explanation
    ) {
      return res.status(400).json({
        error:
          'Subject, lecture, question stem, all 4 options, correct answer (A–D), and explanation are required.',
      });
    }

    const saved = await upsertQuestionAdmin(
      { uid: req.user!.uid, email: req.user!.email },
      {
        id: id ? Number(id) : undefined,
        subjectId: Number(subjectId),
        lectureId: Number(lectureId),
        questionText: String(questionText),
        optionA: String(optionA),
        optionB: String(optionB),
        optionC: String(optionC),
        optionD: String(optionD),
        correctAnswer: String(correctAnswer).toUpperCase() as any,
        explanation: String(explanation),
        explanationA: explanationA ? String(explanationA) : '',
        explanationB: explanationB ? String(explanationB) : '',
        explanationC: explanationC ? String(explanationC) : '',
        explanationD: explanationD ? String(explanationD) : '',
        difficulty: difficulty || 'Medium',
        tags: tags ? String(tags) : '',
        status: status || 'published',
      }
    );
    return res.json({ question: saved });
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to save question.', 400);
  }
});

app.delete(
  '/api/admin/subjects/:id',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const subjectId = Number(req.params.id);
      const result = await deleteSubjectAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        subjectId
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to delete subject.', 400);
    }
  }
);

app.delete(
  '/api/admin/lectures/:id',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const lectureId = Number(req.params.id);
      const result = await deleteLectureAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        lectureId
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to delete lecture.', 400);
    }
  }
);

app.delete(
  '/api/admin/question-banks/:id',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const bankId = Number(req.params.id);
      const result = await deleteQuestionBankAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        bankId
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to delete quiz bank.', 400);
    }
  }
);

app.delete(
  '/api/admin/questions/:id',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const questionId = Number(req.params.id);
      const result = await deleteOrArchiveQuestionAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        questionId
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to delete question.', 400);
    }
  }
);

app.delete(
  '/api/admin/sessions/:id',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const sessionId = Number(req.params.id);
      const result = await deleteExamSessionAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        sessionId
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to delete quiz session.', 400);
    }
  }
);

app.put(
  '/api/admin/users/:uid/role',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const targetUid = String(req.params.uid);
      const role = req.body?.role === 'admin' ? 'admin' : 'student';
      const result = await updateUserRoleAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        targetUid,
        role
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to update user role.', 400);
    }
  }
);

app.delete(
  '/api/admin/users/:uid',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const targetUid = String(req.params.uid);
      const result = await deleteUserAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        targetUid
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to delete user.', 400);
    }
  }
);

app.get('/api/admin/csv-template', requireAuth, requireAdmin, (_req, res) => {
  const csv = getSampleCsvTemplate();
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="medatlas_mcq_template.csv"');
  res.send(csv);
});

app.post(
  '/api/admin/import/preview',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const { csvContent } = req.body || {};
      if (!csvContent || typeof csvContent !== 'string') {
        return res.status(400).json({ error: 'CSV content is required for validation.' });
      }
      const preview = await previewCsvImportAdmin(csvContent);
      return res.json(preview);
    } catch (error) {
      return sendErrorResponse(res, error, 'Failed to validate CSV.', 400);
    }
  }
);

app.post(
  '/api/admin/import/execute',
  requireAuth,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const { fileName, csvContent } = req.body || {};
      if (!csvContent || typeof csvContent !== 'string') {
        return res.status(400).json({ error: 'CSV content is required for import.' });
      }
      const result = await executeCsvImportAdmin(
        { uid: req.user!.uid, email: req.user!.email },
        fileName || 'upload.csv',
        csvContent
      );
      return res.json(result);
    } catch (error) {
      return sendErrorResponse(res, error, 'CSV import failed.', 400);
    }
  }
);

app.get('/api/admin/export-csv', requireAuth, requireAdmin, async (_req, res) => {
  try {
    const csv = await exportQuestionBankCsvAdmin();
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="medatlas_question_bank_backup.csv"'
    );
    return res.send(csv);
  } catch (error) {
    return sendErrorResponse(res, error, 'Failed to export question bank.', 500);
  }
});

// ============================================================================
// VITE DEV SERVER / PRODUCTION STATIC SERVING
// ============================================================================
async function startServer() {
  const PORT = Number(process.env.PORT) || 3000;

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MedAtlas MCQ server running on http://localhost:${PORT}`);
  });
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}
