import { eq, and, desc, asc, inArray } from 'drizzle-orm';
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
} from './schema.ts';
import { INITIAL_CURRICULUM_SEED } from './seed-data.ts';
import {
  computeContentHash,
  createOptionPermutation,
  formatQuestionForClient,
  resolveCanonicalOption,
  scoreExamSession,
  selectPracticeQuestions,
  computeTopicPerformance,
  parseAndValidateCsvQuestions,
} from '../lib/mcq-engine.ts';
import type {
  OptionKey,
  OptionPermutation,
  DifficultyLevel,
  ContentStatus,
  CanonicalQuestion,
} from '../lib/mcq-engine.ts';
import { hashPassword } from '../middleware/auth.ts';

export const SOLE_ADMIN_EMAIL = 'zeyadzedan098@gmail.com';

export function isSoleAdminEmail(email: string): boolean {
  return email.toLowerCase().trim() === SOLE_ADMIN_EMAIL;
}

let isSeeded = false;

export async function ensureSeededDatabase() {
  if (isSeeded) return;
  try {
    const existingSubjects = await db.select().from(subjects);
    if (existingSubjects.length > 0) {
      isSeeded = true;
      return;
    }

    for (const subjSeed of INITIAL_CURRICULUM_SEED) {
      const [insertedSubj] = await db
        .insert(subjects)
        .values({
          slug: subjSeed.slug,
          title: subjSeed.title,
          description: subjSeed.description,
          displayOrder: subjSeed.displayOrder,
          status: 'published',
        })
        .returning();

      for (const lectSeed of subjSeed.lectures) {
        const [insertedLect] = await db
          .insert(lectures)
          .values({
            subjectId: insertedSubj.id,
            title: lectSeed.title,
            description: lectSeed.description,
            lectureNumber: lectSeed.lectureNumber,
            educationalNotes: lectSeed.educationalNotes,
            estimatedMinutes: lectSeed.estimatedMinutes,
            status: 'published',
          })
          .returning();

        const [practiceBank] = await db
          .insert(questionBanks)
          .values({
            subjectId: insertedSubj.id,
            lectureId: insertedLect.id,
            title: `${lectSeed.title} — Practice Bank`,
            description: `Untimed formative study questions and explanations for ${lectSeed.title}.`,
            bankType: 'practice',
            timeLimitMinutes: null,
            isPremium: false,
            status: 'published',
          })
          .returning();

        await db.insert(questionBanks).values({
          subjectId: insertedSubj.id,
          lectureId: insertedLect.id,
          title: `${lectSeed.title} — Timed Mock Exam`,
          description: `Exam-simulation assessment with hidden answers until submission.`,
          bankType: 'mock_exam',
          timeLimitMinutes: 15,
          isPremium: false,
          status: 'published',
        });

        for (const qSeed of lectSeed.questions) {
          const contentHash = computeContentHash(
            `${subjSeed.title}|${lectSeed.title}|${qSeed.questionText}|${qSeed.optionA}|${qSeed.optionB}|${qSeed.optionC}|${qSeed.optionD}`
          );

          await db.insert(questions).values({
            subjectId: insertedSubj.id,
            lectureId: insertedLect.id,
            questionBankId: practiceBank.id,
            questionText: qSeed.questionText,
            optionA: qSeed.optionA,
            optionB: qSeed.optionB,
            optionC: qSeed.optionC,
            optionD: qSeed.optionD,
            correctAnswer: qSeed.correctAnswer,
            explanation: qSeed.explanation,
            explanationA: qSeed.explanationA,
            explanationB: qSeed.explanationB,
            explanationC: qSeed.explanationC,
            explanationD: qSeed.explanationD,
            difficulty: qSeed.difficulty,
            tags: qSeed.tags,
            diagramSvg: qSeed.diagramSvg || '',
            status: 'published',
            version: 1,
            contentHash,
          });
        }
      }
    }

    isSeeded = true;
  } catch (error) {
    console.error('Database seed check failed:', error);
    throw new Error('Failed to initialize curriculum database.', { cause: error });
  }
}

export async function getOrCreateUser(
  uid: string,
  email: string,
  displayName?: string
) {
  try {
    await ensureSeededDatabase();
    const normalizedEmail = email.toLowerCase().trim();
    const expectedRole = isSoleAdminEmail(normalizedEmail) ? 'admin' : 'student';
    const defaultName =
      displayName?.trim() || normalizedEmail.split('@')[0] || 'Medical Student';

    const existingByUid = await db
      .select()
      .from(users)
      .where(eq(users.uid, uid));

    if (existingByUid.length > 0) {
      const user = existingByUid[0];
      if (user.role !== expectedRole) {
        const [updatedRoleUser] = await db
          .update(users)
          .set({ role: expectedRole, updatedAt: new Date() })
          .where(eq(users.uid, uid))
          .returning();
        return updatedRoleUser;
      }
      return user;
    }

    const existingByEmail = await db
      .select()
      .from(users)
      .where(eq(users.email, normalizedEmail));

    if (existingByEmail.length > 0) {
      const [updated] = await db
        .update(users)
        .set({
          uid,
          role: expectedRole,
          updatedAt: new Date(),
        })
        .where(eq(users.email, normalizedEmail))
        .returning();
      return updated;
    }

    const [created] = await db
      .insert(users)
      .values({
        uid,
        email: normalizedEmail,
        displayName: defaultName,
        role: expectedRole,
        subscriptionTier: 'free_trial',
        subscriptionStatus: 'active',
        emailVerified: true,
      })
      .onConflictDoUpdate({
        target: users.uid,
        set: {
          email: normalizedEmail,
          role: expectedRole,
          updatedAt: new Date(),
        },
      })
      .returning();

    return created;
  } catch (error) {
    console.error('Database error in getOrCreateUser:', error);
    throw new Error('Failed to synchronize user profile.', { cause: error });
  }
}

export async function registerEmailPasswordUser(
  email: string,
  password: string,
  displayName: string
) {
  try {
    await ensureSeededDatabase();
    const normalizedEmail = email.toLowerCase().trim();
    const expectedRole = isSoleAdminEmail(normalizedEmail) ? 'admin' : 'student';
    const passwordHash = hashPassword(password);

    const existing = await db
      .select()
      .from(users)
      .where(eq(users.email, normalizedEmail));

    if (existing.length > 0) {
      // If account was previously created via Google Sign-In without a passwordHash, attach the passwordHash
      if (!existing[0].passwordHash) {
        const [linked] = await db
          .update(users)
          .set({
            displayName: displayName.trim() || existing[0].displayName,
            passwordHash,
            role: expectedRole,
            updatedAt: new Date(),
          })
          .where(eq(users.email, normalizedEmail))
          .returning();
        return linked;
      }
      throw new Error('An account with this email address already exists.');
    }

    const uid = `usr_${computeContentHash(`${normalizedEmail}_${Date.now()}`)}`;

    const [created] = await db
      .insert(users)
      .values({
        uid,
        email: normalizedEmail,
        displayName: displayName.trim() || normalizedEmail.split('@')[0],
        passwordHash,
        role: expectedRole,
        subscriptionTier: 'free_trial',
        subscriptionStatus: 'active',
        emailVerified: true,
      })
      .returning();

    return created;
  } catch (error: any) {
    if (error.message?.includes('already exists')) throw error;
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
    if (!user) return null;

    const expectedRole = isSoleAdminEmail(normalizedEmail) ? 'admin' : 'student';
    if (user.role !== expectedRole) {
      const [normalizedUser] = await db
        .update(users)
        .set({ role: expectedRole, updatedAt: new Date() })
        .where(eq(users.uid, user.uid))
        .returning();
      return normalizedUser;
    }
    return user;
  } catch (error) {
    console.error('Error finding user by email:', error);
    throw new Error('Database lookup failed.', { cause: error });
  }
}

export async function resetUserPasswordByEmail(email: string, newPassword: string) {
  try {
    const user = await findUserByEmail(email);
    if (!user) {
      throw new Error('No registered account found for that email address.');
    }
    const [updated] = await db
      .update(users)
      .set({
        passwordHash: hashPassword(newPassword),
        updatedAt: new Date(),
      })
      .where(eq(users.uid, user.uid))
      .returning();
    return updated;
  } catch (error: any) {
    if (error.message?.includes('No registered account')) throw error;
    console.error('Error resetting password:', error);
    throw new Error('Failed to update password.', { cause: error });
  }
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
    return updated;
  } catch (error) {
    console.error('Error updating user profile:', error);
    throw new Error('Failed to update user profile.', { cause: error });
  }
}

export async function deleteUserAccount(uid: string) {
  try {
    // Delete all private records belonging to this student
    await db.delete(bookmarks).where(eq(bookmarks.userUid, uid));
    await db.delete(questionAttempts).where(eq(questionAttempts.userUid, uid));
    await db.delete(examSessions).where(eq(examSessions.userUid, uid));
    await db.delete(users).where(eq(users.uid, uid));
    return { deleted: true };
  } catch (error) {
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
      throw new Error(
        selection.shortfallNotice || 'No published questions match your selected filters.'
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
        ? (params.timeLimitMinutes ?? Math.max(5, selection.selectedQuestions.length * 2)) * 60
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
    if (error.message?.includes('No published questions')) throw error;
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
      throw new Error('Forbidden or not found: Exam session does not belong to this account.');
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

    // Server-side remaining timer calculation for Exam Mode
    let remainingSeconds: number | null = null;
    if (session.timeLimitSeconds !== null) {
      if (session.status === 'completed') {
        remainingSeconds = Math.max(0, session.timeLimitSeconds - session.elapsedSeconds);
      } else {
        const serverElapsed = Math.floor(
          (Date.now() - new Date(session.startedAt).getTime()) / 1000
        );
        remainingSeconds = Math.max(0, session.timeLimitSeconds - serverElapsed);
      }
    }

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
      elapsedSeconds: session.elapsedSeconds,
      remainingSeconds,
      shuffleOptions: session.shuffleOptions,
      startedAt: session.startedAt,
      completedAt: session.completedAt,
      questions: formattedQuestions,
    };
  } catch (error: any) {
    if (error.message?.includes('Forbidden or not found')) throw error;
    console.error('Error loading exam session:', error);
    throw new Error('Failed to load exam session.', { cause: error });
  }
}

/**
 * Records an answer selection for a single question inside a session.
 * In Study/Custom mode, submitting immediately reveals feedback for that question.
 * In Exam mode, records the selected choice without revealing the answer.
 */
export async function saveSessionQuestionAnswer(
  userUid: string,
  sessionId: number,
  questionId: number,
  displayedOption: OptionKey | null,
  lockAnswer: boolean,
  elapsedSeconds?: number
) {
  try {
    const rows = await db
      .select()
      .from(examSessions)
      .where(and(eq(examSessions.id, sessionId), eq(examSessions.userUid, userUid)));

    if (rows.length === 0) {
      throw new Error('Forbidden: Session not found for this user.');
    }

    const session = rows[0];
    if (session.status === 'completed') {
      return getExamSessionForStudent(userUid, sessionId);
    }

    const orderItems: SessionOrderItem[] = JSON.parse(session.questionOrderJson || '[]');
    const targetItem = orderItems.find((item) => item.questionId === questionId);
    if (!targetItem) {
      throw new Error('Question does not belong to this session.');
    }

    targetItem.selectedDisplayed = displayedOption;
    targetItem.selectedCanonical = resolveCanonicalOption(
      displayedOption,
      targetItem.permutation
    );
    if (lockAnswer) {
      targetItem.submitted = true;
    }

    await db
      .update(examSessions)
      .set({
        questionOrderJson: JSON.stringify(orderItems),
        elapsedSeconds:
          typeof elapsedSeconds === 'number'
            ? Math.max(session.elapsedSeconds, elapsedSeconds)
            : session.elapsedSeconds,
      })
      .where(and(eq(examSessions.id, sessionId), eq(examSessions.userUid, userUid)));

    return getExamSessionForStudent(userUid, sessionId);
  } catch (error: any) {
    if (error.message?.includes('Forbidden')) throw error;
    console.error('Error saving question answer:', error);
    throw new Error('Failed to save question response.', { cause: error });
  }
}

/**
 * Completes and grades an Exam or Study session idempotently.
 * Prevents duplicate attempt insertions if submitted twice, and records immutable snapshots
 * of each question so future admin edits do not alter historical student scores.
 */
export async function completeExamSession(
  userUid: string,
  sessionId: number,
  finalDisplayedAnswers?: Record<number, OptionKey | null>,
  clientElapsedSeconds?: number
) {
  try {
    const rows = await db
      .select()
      .from(examSessions)
      .where(and(eq(examSessions.id, sessionId), eq(examSessions.userUid, userUid)));

    if (rows.length === 0) {
      throw new Error('Forbidden: Session not found for this user.');
    }

    const session = rows[0];
    // Idempotency guard: if already completed, return the completed session without duplicating attempts!
    if (session.status === 'completed') {
      return getExamSessionForStudent(userUid, sessionId);
    }

    const orderItems: SessionOrderItem[] = JSON.parse(session.questionOrderJson || '[]');
    if (finalDisplayedAnswers) {
      for (const item of orderItems) {
        if (item.questionId in finalDisplayedAnswers) {
          const disp = finalDisplayedAnswers[item.questionId];
          item.selectedDisplayed = disp;
          item.selectedCanonical = resolveCanonicalOption(disp, item.permutation);
        }
        item.submitted = true;
      }
    } else {
      for (const item of orderItems) {
        item.submitted = true;
      }
    }

    const qIds = orderItems.map((i) => i.questionId);
    const dbQuestions =
      qIds.length > 0
        ? await db.select().from(questions).where(inArray(questions.id, qIds))
        : [];
    const allSubjects = await db.select().from(subjects);
    const allLectures = await db.select().from(lectures);

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
    const serverElapsed = Math.max(
      1,
      Math.floor((Date.now() - new Date(session.startedAt).getTime()) / 1000)
    );
    const finalElapsed =
      session.timeLimitSeconds !== null
        ? Math.min(session.timeLimitSeconds, clientElapsedSeconds || serverElapsed)
        : clientElapsedSeconds || serverElapsed;

    await db
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
      .where(and(eq(examSessions.id, sessionId), eq(examSessions.userUid, userUid)));

    // Remove any partial attempt rows for this sessionId before inserting the finalized set
    await db
      .delete(questionAttempts)
      .where(
        and(eq(questionAttempts.sessionId, sessionId), eq(questionAttempts.userUid, userUid))
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

      await db.insert(questionAttempts).values({
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
      });
    }

    return getExamSessionForStudent(userUid, sessionId);
  } catch (error: any) {
    if (error.message?.includes('Forbidden')) throw error;
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
      subjects: allSubjects,
      lectures: allLectures.map((l) => ({
        ...l,
        subjectTitle: sMap.get(l.subjectId) || 'Unknown Subject',
      })),
      questionBanks: allBanks,
      questions: allQuestions.map((q) => ({
        ...q,
        subjectTitle: sMap.get(q.subjectId) || 'Unknown Subject',
        lectureTitle: lMap.get(q.lectureId) || 'Unknown Lecture',
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

    const [created] = await db
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
    await db.insert(questionBanks).values({
      subjectId: created.subjectId,
      lectureId: created.id,
      title: `${created.title} — Practice Bank`,
      description: `Formative practice bank for ${created.title}.`,
      bankType: 'practice',
      status: 'published',
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
 * Safe archival or deletion of a question:
 * If the question has already been used in student attempts, archives it instead of destroying historical records!
 */
export async function deleteOrArchiveQuestionAdmin(
  admin: { uid: string; email: string },
  questionId: number
) {
  try {
    const existingAttempts = await db
      .select()
      .from(questionAttempts)
      .where(eq(questionAttempts.questionId, questionId));

    if (existingAttempts.length > 0) {
      const [archived] = await db
        .update(questions)
        .set({ status: 'archived', updatedAt: new Date() })
        .where(eq(questions.id, questionId))
        .returning();

      await logAdminAction(
        admin.uid,
        admin.email,
        'ARCHIVE_QUESTION',
        'question',
        questionId,
        `Archived question #${questionId} instead of hard deletion because ${existingAttempts.length} historical student attempt(s) reference it.`
      );
      return {
        action: 'archived',
        message: `Question #${questionId} has ${existingAttempts.length} historical student attempt(s); it was safely archived to preserve historical exam records.`,
        question: archived,
      };
    }

    await db.delete(questions).where(eq(questions.id, questionId));
    await logAdminAction(
      admin.uid,
      admin.email,
      'DELETE_QUESTION',
      'question',
      questionId,
      `Permanently deleted unused question #${questionId}`
    );
    return {
      action: 'deleted',
      message: `Unused question #${questionId} was permanently deleted.`,
    };
  } catch (error) {
    console.error('Error deleting/archiving question:', error);
    throw new Error('Failed to delete or archive question.', { cause: error });
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
      throw new Error(report.headerErrors.join(' '));
    }

    // Check if the exact same file was already imported
    const existingBatch = await db
      .select()
      .from(importBatches)
      .where(eq(importBatches.fileHash, report.fileHash));

    if (existingBatch.length > 0 && report.validCount === 0) {
      throw new Error(
        `Duplicate file submission prevented: "${fileName}" was already imported on ${new Date(
          existingBatch[0].createdAt
        ).toLocaleString()}.`
      );
    }

    const allSubjects = await db.select().from(subjects);
    const allLectures = await db.select().from(lectures);

    const subjectByTitle = new Map(
      allSubjects.map((s) => [s.title.toLowerCase().trim(), s])
    );
    const lectureByKey = new Map(
      allLectures.map((l) => [`${l.subjectId}:${l.title.toLowerCase().trim()}`, l])
    );

    let importedCount = 0;
    const skippedCount = report.duplicateCount;
    const failedCount = report.invalidCount;

    const validRows = report.rows.filter((r) => r.isValid);

    for (const row of validRows) {
      const subjKey = row.subject.toLowerCase().trim();
      let subj = subjectByTitle.get(subjKey);
      if (!subj) {
        const slug = `${subjKey.replace(/[^a-z0-9]+/g, '-')}-${Date.now().toString(36)}`;
        const [newSubj] = await db
          .insert(subjects)
          .values({
            slug,
            title: row.subject.trim(),
            description: `Imported subject: ${row.subject.trim()}`,
            displayOrder: allSubjects.length + 1,
            status: 'published',
          })
          .returning();
        subj = newSubj;
        subjectByTitle.set(subjKey, subj);
      }

      const lectKey = `${subj.id}:${row.lecture.toLowerCase().trim()}`;
      let lect = lectureByKey.get(lectKey);
      if (!lect) {
        const [newLect] = await db
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

      await db.insert(questions).values({
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

    const [batchRecord] = await db
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

    await logAdminAction(
      admin.uid,
      admin.email,
      'BULK_CSV_IMPORT',
      'import_batch',
      batchRecord.id,
      `Imported ${importedCount} questions from "${fileName}" (${skippedCount} duplicates skipped, ${failedCount} invalid rows rejected)`
    );

    return {
      batch: batchRecord,
      report,
    };
  } catch (error: any) {
    if (error.message?.includes('Duplicate file submission') || error.message?.includes('Missing required CSV')) {
      throw error;
    }
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
