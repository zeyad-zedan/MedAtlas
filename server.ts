import express, { Response, NextFunction } from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import * as dotenv from 'dotenv';
import {
  requireAuth,
  AuthRequest,
  verifyPassword,
  createServerSessionToken,
} from './src/middleware/auth.ts';
import {
  ensureSeededDatabase,
  getOrCreateUser,
  registerEmailPasswordUser,
  findUserByEmail,
  resetUserPasswordByEmail,
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
  deleteOrArchiveQuestionAdmin,
  previewCsvImportAdmin,
  executeCsvImportAdmin,
  exportQuestionBankCsvAdmin,
} from './src/db/repository.ts';
import { getSampleCsvTemplate } from './src/lib/mcq-engine.ts';

dotenv.config();

const app = express();
app.use(express.json({ limit: '5mb' }));

// Simple in-memory rate limiter for auth and sensitive mutations
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
function rateLimit(maxRequests: number, windowMs: number) {
  return (req: express.Request, res: Response, next: NextFunction) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const record = rateLimitMap.get(key);
    if (!record || now > record.resetAt) {
      rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (record.count >= maxRequests) {
      return res
        .status(429)
        .json({ error: 'Too many requests. Please wait a moment and try again.' });
    }
    record.count++;
    return next();
  };
}

// Middleware to verify database-backed Administrator role
const requireAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const dbUser = await getOrCreateUser(req.user.uid, req.user.email, req.user.name);
    if (!dbUser || dbUser.role !== 'admin') {
      return res
        .status(403)
        .json({ error: 'Forbidden: Administrator privileges are required for this operation.' });
    }
    return next();
  } catch (error: any) {
    console.error('Admin verification failed:', error);
    return res.status(500).json({ error: 'Failed to verify administrator permissions.' });
  }
};

// ============================================================================
// PUBLIC CATALOG API
// ============================================================================
app.get('/api/catalog', async (_req, res) => {
  try {
    const catalog = await getPublishedCatalog();
    res.json(catalog);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to load catalog.' });
  }
});

// ============================================================================
// AUTHENTICATION & ACCOUNT API
// ============================================================================
app.post('/api/auth/register', rateLimit(15, 60_000), async (req, res) => {
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
      return res
        .status(400)
        .json({ error: 'Please enter your full name or display name (at least 2 characters).' });
    }

    const user = await registerEmailPasswordUser(email, password, displayName);
    const token = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
    });

    const { passwordHash: _ph, ...safeUser } = user;
    return res.status(201).json({ token, user: safeUser });
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Registration failed.' });
  }
});

app.post('/api/auth/login', rateLimit(20, 60_000), async (req, res) => {
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
    });

    const { passwordHash: _ph, ...safeUser } = user;
    return res.json({ token, user: safeUser });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Login failed.' });
  }
});

app.post('/api/auth/demo', rateLimit(30, 60_000), async (req, res) => {
  try {
    await ensureSeededDatabase();
    const role = req.body?.role === 'admin' ? 'admin' : 'student';
    const email =
      role === 'admin' ? 'admin.demo@medatlas.edu' : 'student.demo@medatlas.edu';
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: 'Demo account not found.' });
    }
    const token = createServerSessionToken({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
    });
    const { passwordHash: _ph, ...safeUser } = user;
    return res.json({ token, user: safeUser });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Demo login failed.' });
  }
});

app.post('/api/auth/reset-password', rateLimit(10, 60_000), async (req, res) => {
  try {
    const { email, newPassword } = req.body || {};
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Please enter a valid account email address.' });
    }
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return res
        .status(400)
        .json({ error: 'New password must be at least 8 characters long.' });
    }
    await resetUserPasswordByEmail(email, newPassword);
    return res.json({
      message: 'Your password has been updated. You may now sign in with your new password.',
    });
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Password recovery failed.' });
  }
});

app.get('/api/auth/me', requireAuth, async (req: AuthRequest, res) => {
  try {
    const user = await getOrCreateUser(req.user!.uid, req.user!.email, req.user!.name);
    const { passwordHash: _ph, ...safeUser } = user;
    return res.json({ user: safeUser });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to load profile.' });
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
    const { passwordHash: _ph, ...safeUser } = updated;
    return res.json({ user: safeUser });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to update profile.' });
  }
});

app.delete('/api/auth/account', requireAuth, async (req: AuthRequest, res) => {
  try {
    const result = await deleteUserAccount(req.user!.uid);
    return res.json(result);
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to delete account.' });
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
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Could not start session.' });
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
  } catch (error: any) {
    const status = error.message?.includes('Forbidden') ? 403 : 404;
    return res.status(status).json({ error: error.message || 'Session not found.' });
  }
});

app.post('/api/sessions/:id/answer', requireAuth, async (req: AuthRequest, res) => {
  try {
    const sessionId = Number(req.params.id);
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
  } catch (error: any) {
    const status = error.message?.includes('Forbidden') ? 403 : 400;
    return res.status(status).json({ error: error.message || 'Failed to record answer.' });
  }
});

app.post('/api/sessions/:id/complete', requireAuth, async (req: AuthRequest, res) => {
  try {
    const sessionId = Number(req.params.id);
    const { answers, elapsedSeconds } = req.body || {};
    const session = await completeExamSession(
      req.user!.uid,
      sessionId,
      answers,
      typeof elapsedSeconds === 'number' ? elapsedSeconds : undefined
    );
    return res.json({ session });
  } catch (error: any) {
    const status = error.message?.includes('Forbidden') ? 403 : 400;
    return res.status(status).json({ error: error.message || 'Failed to complete session.' });
  }
});

app.get('/api/dashboard', requireAuth, async (req: AuthRequest, res) => {
  try {
    const analytics = await getStudentDashboardAnalytics(req.user!.uid);
    return res.json(analytics);
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to load dashboard.' });
  }
});

app.get('/api/bookmarks', requireAuth, async (req: AuthRequest, res) => {
  try {
    const data = await getStudentBookmarksAndReview(req.user!.uid);
    return res.json(data);
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to load bookmarks.' });
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
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to toggle bookmark.' });
  }
});

// ============================================================================
// PROTECTED ADMINISTRATOR API
// ============================================================================
app.get('/api/admin/overview', requireAuth, requireAdmin, async (_req: AuthRequest, res) => {
  try {
    const data = await getAdminDashboardData();
    return res.json(data);
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to load admin overview.' });
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
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Failed to save subject.' });
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
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Failed to save lecture.' });
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
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Failed to save question.' });
  }
});

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
    } catch (error: any) {
      return res.status(400).json({ error: error.message || 'Failed to delete question.' });
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
    } catch (error: any) {
      return res.status(400).json({ error: error.message || 'Failed to validate CSV.' });
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
    } catch (error: any) {
      return res.status(400).json({ error: error.message || 'CSV import failed.' });
    }
  }
);

app.get('/api/admin/export-csv', requireAuth, requireAdmin, async (_req, res) => {
  try {
    const csv = await exportQuestionBankCsvAdmin();
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="medatlas_question_bank_backup.csv"');
    res.send(csv);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to export question bank.' });
  }
});

// ============================================================================
// VITE DEV SERVER / PRODUCTION STATIC SERVING
// ============================================================================
async function startServer() {
  const PORT = 3000;

  if (process.env.NODE_ENV !== 'production') {
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

startServer();
