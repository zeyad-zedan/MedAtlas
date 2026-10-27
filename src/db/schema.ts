import { relations } from 'drizzle-orm';
import {
  boolean,
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  uid: text('uid').notNull().unique(),
  email: text('email').notNull().unique(),
  displayName: text('display_name').notNull(),
  passwordHash: text('password_hash'),
  authProvider: text('auth_provider').notNull().default('local'), // 'local' | 'firebase' | 'linked'
  tokenVersion: integer('token_version').notNull().default(1),
  accountStatus: text('account_status').notNull().default('active'), // 'active' | 'deleted' | 'suspended'
  deletedAt: timestamp('deleted_at'),
  role: text('role').notNull().default('student'), // 'student' | 'admin'
  subscriptionTier: text('subscription_tier').notNull().default('free_trial'), // 'free_trial' | 'free' | 'premium_monthly' | 'premium_annual'
  subscriptionStatus: text('subscription_status').notNull().default('active'), // 'active' | 'trialing' | 'expired' | 'canceled'
  subscriptionExpiresAt: timestamp('subscription_expires_at'),
  emailVerified: boolean('email_verified').notNull().default(false),
  preferences: text('preferences').notNull().default('{}'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const passwordResetTokens = pgTable('password_reset_tokens', {
  id: serial('id').primaryKey(),
  userUid: text('user_uid').notNull(),
  tokenHash: text('token_hash').notNull().unique(),
  expiresAt: timestamp('expires_at').notNull(),
  consumedAt: timestamp('consumed_at'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const deletedAccounts = pgTable('deleted_accounts', {
  id: serial('id').primaryKey(),
  uid: text('uid').notNull().unique(),
  emailHash: text('email_hash').notNull(),
  deletedAt: timestamp('deleted_at').defaultNow().notNull(),
});

export const subjects = pgTable('subjects', {
  id: serial('id').primaryKey(),
  slug: text('slug').notNull().unique(),
  title: text('title').notNull(),
  description: text('description').notNull(),
  displayOrder: integer('display_order').notNull().default(1),
  status: text('status').notNull().default('published'), // 'draft' | 'published' | 'archived'
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const lectures = pgTable('lectures', {
  id: serial('id').primaryKey(),
  subjectId: integer('subject_id')
    .references(() => subjects.id, { onDelete: 'cascade' })
    .notNull(),
  title: text('title').notNull(),
  description: text('description').notNull(),
  lectureNumber: integer('lecture_number').notNull().default(1),
  educationalNotes: text('educational_notes').notNull().default(''),
  estimatedMinutes: integer('estimated_minutes').notNull().default(30),
  status: text('status').notNull().default('published'), // 'draft' | 'published' | 'archived'
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const questionBanks = pgTable('question_banks', {
  id: serial('id').primaryKey(),
  subjectId: integer('subject_id')
    .references(() => subjects.id, { onDelete: 'cascade' })
    .notNull(),
  lectureId: integer('lecture_id')
    .references(() => lectures.id, { onDelete: 'cascade' })
    .notNull(),
  title: text('title').notNull(),
  description: text('description').notNull().default(''),
  bankType: text('bank_type').notNull().default('practice'), // 'practice' | 'mock_exam'
  timeLimitMinutes: integer('time_limit_minutes'),
  isPremium: boolean('is_premium').notNull().default(false),
  status: text('status').notNull().default('published'), // 'draft' | 'published' | 'archived'
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const questions = pgTable('questions', {
  id: serial('id').primaryKey(),
  subjectId: integer('subject_id')
    .references(() => subjects.id, { onDelete: 'cascade' })
    .notNull(),
  lectureId: integer('lecture_id')
    .references(() => lectures.id, { onDelete: 'cascade' })
    .notNull(),
  questionBankId: integer('question_bank_id').references(() => questionBanks.id, {
    onDelete: 'set null',
  }),
  questionText: text('question_text').notNull(),
  optionA: text('option_a').notNull(),
  optionB: text('option_b').notNull(),
  optionC: text('option_c').notNull(),
  optionD: text('option_d').notNull(),
  correctAnswer: text('correct_answer').notNull(), // 'A' | 'B' | 'C' | 'D'
  explanation: text('explanation').notNull(),
  explanationA: text('explanation_a').notNull().default(''),
  explanationB: text('explanation_b').notNull().default(''),
  explanationC: text('explanation_c').notNull().default(''),
  explanationD: text('explanation_d').notNull().default(''),
  difficulty: text('difficulty').notNull().default('Medium'), // 'Easy' | 'Medium' | 'Hard'
  tags: text('tags').notNull().default(''),
  diagramSvg: text('diagram_svg').notNull().default(''),
  status: text('status').notNull().default('published'), // 'draft' | 'published' | 'archived'
  version: integer('version').notNull().default(1),
  contentHash: text('content_hash').notNull().default(''),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const examSessions = pgTable('exam_sessions', {
  id: serial('id').primaryKey(),
  userUid: text('user_uid').notNull(),
  title: text('title').notNull(),
  mode: text('mode').notNull(), // 'study' | 'exam' | 'custom'
  subjectId: integer('subject_id').references(() => subjects.id, { onDelete: 'set null' }),
  lectureId: integer('lecture_id').references(() => lectures.id, { onDelete: 'set null' }),
  status: text('status').notNull().default('in_progress'), // 'in_progress' | 'completed' | 'abandoned'
  totalQuestions: integer('total_questions').notNull(),
  correctCount: integer('correct_count').notNull().default(0),
  incorrectCount: integer('incorrect_count').notNull().default(0),
  unansweredCount: integer('unanswered_count').notNull().default(0),
  scorePercentage: integer('score_percentage').notNull().default(0),
  timeLimitSeconds: integer('time_limit_seconds'),
  elapsedSeconds: integer('elapsed_seconds').notNull().default(0),
  shuffleOptions: boolean('shuffle_options').notNull().default(false),
  questionOrderJson: text('question_order_json').notNull(),
  startedAt: timestamp('started_at').defaultNow().notNull(),
  completedAt: timestamp('completed_at'),
});

export const questionAttempts = pgTable(
  'question_attempts',
  {
    id: serial('id').primaryKey(),
    sessionId: integer('session_id')
      .references(() => examSessions.id, { onDelete: 'cascade' })
      .notNull(),
    userUid: text('user_uid').notNull(),
    questionId: integer('question_id').references(() => questions.id, { onDelete: 'set null' }),
    subjectId: integer('subject_id'),
    lectureId: integer('lecture_id'),
    selectedOption: text('selected_option'), // 'A' | 'B' | 'C' | 'D' | null
    correctOptionSnapshot: text('correct_option_snapshot').notNull(),
    isCorrect: boolean('is_correct').notNull().default(false),
    questionSnapshotJson: text('question_snapshot_json').notNull(),
    timeSpentSeconds: integer('time_spent_seconds').notNull().default(0),
    answeredAt: timestamp('answered_at').defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex('uq_session_question_attempt').on(table.sessionId, table.questionId),
  ]
);

export const bookmarks = pgTable('bookmarks', {
  id: serial('id').primaryKey(),
  userUid: text('user_uid').notNull(),
  questionId: integer('question_id')
    .references(() => questions.id, { onDelete: 'cascade' })
    .notNull(),
  note: text('note').notNull().default(''),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const importBatches = pgTable('import_batches', {
  id: serial('id').primaryKey(),
  adminUid: text('admin_uid').notNull(),
  fileName: text('file_name').notNull(),
  fileHash: text('file_hash').notNull(),
  totalRows: integer('total_rows').notNull(),
  importedCount: integer('imported_count').notNull(),
  skippedCount: integer('skipped_count').notNull(),
  failedCount: integer('failed_count').notNull(),
  summaryJson: text('summary_json').notNull().default('{}'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const adminAuditLogs = pgTable('admin_audit_logs', {
  id: serial('id').primaryKey(),
  adminUid: text('admin_uid').notNull(),
  adminEmail: text('admin_email').notNull(),
  action: text('action').notNull(),
  targetType: text('target_type').notNull(),
  targetId: text('target_id').notNull(),
  details: text('details').notNull().default(''),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// Relations
export const subjectsRelations = relations(subjects, ({ many }) => ({
  lectures: many(lectures),
  questionBanks: many(questionBanks),
  questions: many(questions),
}));

export const lecturesRelations = relations(lectures, ({ one, many }) => ({
  subject: one(subjects, {
    fields: [lectures.subjectId],
    references: [subjects.id],
  }),
  questionBanks: many(questionBanks),
  questions: many(questions),
}));

export const questionBanksRelations = relations(questionBanks, ({ one, many }) => ({
  subject: one(subjects, {
    fields: [questionBanks.subjectId],
    references: [subjects.id],
  }),
  lecture: one(lectures, {
    fields: [questionBanks.lectureId],
    references: [lectures.id],
  }),
  questions: many(questions),
}));

export const questionsRelations = relations(questions, ({ one, many }) => ({
  subject: one(subjects, {
    fields: [questions.subjectId],
    references: [subjects.id],
  }),
  lecture: one(lectures, {
    fields: [questions.lectureId],
    references: [lectures.id],
  }),
  questionBank: one(questionBanks, {
    fields: [questions.questionBankId],
    references: [questionBanks.id],
  }),
  bookmarks: many(bookmarks),
}));

export const examSessionsRelations = relations(examSessions, ({ many }) => ({
  attempts: many(questionAttempts),
}));

export const questionAttemptsRelations = relations(questionAttempts, ({ one }) => ({
  session: one(examSessions, {
    fields: [questionAttempts.sessionId],
    references: [examSessions.id],
  }),
  question: one(questions, {
    fields: [questionAttempts.questionId],
    references: [questions.id],
  }),
}));
