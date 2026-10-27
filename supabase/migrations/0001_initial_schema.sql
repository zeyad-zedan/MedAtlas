-- ============================================================================
-- MedAtlas MCQ — Version-Controlled PostgreSQL Schema, Indexes & RLS Policies
-- Migration: 0001_initial_schema.sql
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.users (
  id SERIAL PRIMARY KEY,
  uid TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT,
  auth_provider TEXT NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'firebase', 'linked')),
  token_version INTEGER NOT NULL DEFAULT 1,
  account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active', 'deleted', 'suspended')),
  deleted_at TIMESTAMP WITHOUT TIME ZONE,
  role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
  subscription_tier TEXT NOT NULL DEFAULT 'free_trial',
  subscription_status TEXT NOT NULL DEFAULT 'active',
  subscription_expires_at TIMESTAMP WITHOUT TIME ZONE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  preferences TEXT NOT NULL DEFAULT '{}',
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.password_reset_tokens (
  id SERIAL PRIMARY KEY,
  user_uid TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
  consumed_at TIMESTAMP WITHOUT TIME ZONE,
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.deleted_accounts (
  id SERIAL PRIMARY KEY,
  uid TEXT NOT NULL UNIQUE,
  email_hash TEXT NOT NULL,
  deleted_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.subjects (
  id SERIAL PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  display_order INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.lectures (
  id SERIAL PRIMARY KEY,
  subject_id INTEGER NOT NULL REFERENCES public.subjects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  lecture_number INTEGER NOT NULL DEFAULT 1,
  educational_notes TEXT NOT NULL DEFAULT '',
  estimated_minutes INTEGER NOT NULL DEFAULT 30,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.question_banks (
  id SERIAL PRIMARY KEY,
  subject_id INTEGER NOT NULL REFERENCES public.subjects(id) ON DELETE CASCADE,
  lecture_id INTEGER NOT NULL REFERENCES public.lectures(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  bank_type TEXT NOT NULL DEFAULT 'practice' CHECK (bank_type IN ('practice', 'mock_exam')),
  time_limit_minutes INTEGER,
  is_premium BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.questions (
  id SERIAL PRIMARY KEY,
  subject_id INTEGER NOT NULL REFERENCES public.subjects(id) ON DELETE CASCADE,
  lecture_id INTEGER NOT NULL REFERENCES public.lectures(id) ON DELETE CASCADE,
  question_bank_id INTEGER REFERENCES public.question_banks(id) ON DELETE SET NULL,
  question_text TEXT NOT NULL,
  option_a TEXT NOT NULL,
  option_b TEXT NOT NULL,
  option_c TEXT NOT NULL,
  option_d TEXT NOT NULL,
  correct_answer TEXT NOT NULL CHECK (correct_answer IN ('A', 'B', 'C', 'D')),
  explanation TEXT NOT NULL,
  explanation_a TEXT NOT NULL DEFAULT '',
  explanation_b TEXT NOT NULL DEFAULT '',
  explanation_c TEXT NOT NULL DEFAULT '',
  explanation_d TEXT NOT NULL DEFAULT '',
  difficulty TEXT NOT NULL DEFAULT 'Medium' CHECK (difficulty IN ('Easy', 'Medium', 'Hard')),
  tags TEXT NOT NULL DEFAULT '',
  diagram_svg TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
  version INTEGER NOT NULL DEFAULT 1,
  content_hash TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.exam_sessions (
  id SERIAL PRIMARY KEY,
  user_uid TEXT NOT NULL,
  title TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('study', 'exam', 'custom')),
  subject_id INTEGER REFERENCES public.subjects(id) ON DELETE SET NULL,
  lecture_id INTEGER REFERENCES public.lectures(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'completed', 'abandoned')),
  total_questions INTEGER NOT NULL,
  correct_count INTEGER NOT NULL DEFAULT 0,
  incorrect_count INTEGER NOT NULL DEFAULT 0,
  unanswered_count INTEGER NOT NULL DEFAULT 0,
  score_percentage INTEGER NOT NULL DEFAULT 0,
  time_limit_seconds INTEGER,
  elapsed_seconds INTEGER NOT NULL DEFAULT 0,
  shuffle_options BOOLEAN NOT NULL DEFAULT FALSE,
  question_order_json TEXT NOT NULL,
  started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE IF NOT EXISTS public.question_attempts (
  id SERIAL PRIMARY KEY,
  session_id INTEGER NOT NULL REFERENCES public.exam_sessions(id) ON DELETE CASCADE,
  user_uid TEXT NOT NULL,
  question_id INTEGER REFERENCES public.questions(id) ON DELETE SET NULL,
  subject_id INTEGER,
  lecture_id INTEGER,
  selected_option TEXT,
  correct_option_snapshot TEXT NOT NULL,
  is_correct BOOLEAN NOT NULL DEFAULT FALSE,
  question_snapshot_json TEXT NOT NULL,
  time_spent_seconds INTEGER NOT NULL DEFAULT 0,
  answered_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_session_question_attempt
  ON public.question_attempts(session_id, question_id);

CREATE TABLE IF NOT EXISTS public.bookmarks (
  id SERIAL PRIMARY KEY,
  user_uid TEXT NOT NULL,
  question_id INTEGER NOT NULL REFERENCES public.questions(id) ON DELETE CASCADE,
  note TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.import_batches (
  id SERIAL PRIMARY KEY,
  admin_uid TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_hash TEXT NOT NULL,
  total_rows INTEGER NOT NULL,
  imported_count INTEGER NOT NULL,
  skipped_count INTEGER NOT NULL,
  failed_count INTEGER NOT NULL,
  summary_json TEXT NOT NULL DEFAULT '{}',
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.admin_audit_logs (
  id SERIAL PRIMARY KEY,
  admin_uid TEXT NOT NULL,
  admin_email TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

-- Performance Indexes for 7,500+ Questions & Multi-Student Concurrency
CREATE INDEX IF NOT EXISTS idx_lectures_subject_status ON public.lectures(subject_id, status);
CREATE INDEX IF NOT EXISTS idx_questions_subject_lecture_status ON public.questions(subject_id, lecture_id, status);
CREATE INDEX IF NOT EXISTS idx_questions_difficulty ON public.questions(difficulty);
CREATE INDEX IF NOT EXISTS idx_questions_content_hash ON public.questions(content_hash);
CREATE INDEX IF NOT EXISTS idx_exam_sessions_user_uid ON public.exam_sessions(user_uid, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_question_attempts_user_uid ON public.question_attempts(user_uid, answered_at DESC);
CREATE INDEX IF NOT EXISTS idx_bookmarks_user_uid ON public.bookmarks(user_uid, question_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_uid ON public.password_reset_tokens(user_uid);

-- Row Level Security (RLS) Enablement & Policies
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.deleted_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lectures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_banks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bookmarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.import_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_audit_logs ENABLE ROW LEVEL SECURITY;
