# MedAtlas MCQ — Medical Education & Examination Platform

MedAtlas MCQ is a full-stack lecture-based multiple-choice question (MCQ) learning platform designed for medical students and medical curriculum administrators.

---

## 1. Project Overview

MedAtlas MCQ organizes medical educational content into a strict academic hierarchy:
**Subject → Lecture → Question Bank → Individual Questions**

Key capabilities and security controls implemented in this release:
- **Hardened Authentication & Account Isolation**:
  - Local Email & Password authentication uses scrypt-salted password hashes and HMAC-SHA256 signed session tokens (`medatlas.v1.<payload>.<sig>`) bound to a database-backed `token_version` and an externally configured high-entropy `AUTH_SESSION_SECRET` (minimum 32 characters; server fails fast on startup if missing or weak).
  - Strictly separated verification paths for local session tokens and Firebase Authentication ID tokens (`firebase-admin`), requiring `email_verified` on provider tokens.
  - Registration (`POST /api/auth/register`) never attaches a password to an existing account or overwrites existing account UIDs. Provider accounts can attach a local password only after authenticating (`POST /api/auth/link-password`).
  - **Cryptographic Single-Use Password Recovery**: `POST /api/auth/forgot-password` generates a 32-byte random token, stores only its SHA-256 hash (`password_reset_tokens.token_hash`) with a 15-minute expiration, invalidates prior unconsumed tokens for that user, and returns an enumeration-safe response. `POST /api/auth/reset-password` requires `{ token, newPassword }`, atomically consumes the token in a PostgreSQL transaction, updates the password hash, and increments `users.token_version` to revoke all prior sessions.
  - **Permanent Account Deletion & Tombstone Enforcement**: Deleting an account (`DELETE /api/auth/account` or `DELETE /api/admin/users/:uid`) atomically removes user records in a PostgreSQL transaction and records a tombstone in `deleted_accounts`. `requireAuth` and `getOrCreateUser` verify active status and tombstone state so deleted accounts are immediately rejected (`401`) and can never be resurrected by `/api/auth/me`.
- **Three Practice & Assessment Modes**:
  - **Mode A (Study Mode)**: Immediate feedback after submitting each question, showing the correct answer, primary synthesis explanation, and individual rationales for Options A, B, C, and D.
  - **Mode B (Exam Mode)**: Server-enforced timed exam simulation. Correct answers and explanations are stripped on the server during active exams. Authoritative exam deadlines (`started_at + time_limit_seconds`) are enforced on the server so manipulated client timers cannot extend exam duration or alter answers after expiration. Exam completion (`completeExamSession`) executes atomically inside a PostgreSQL transaction with `FOR UPDATE` row locking and a unique index (`uq_session_question_attempt`) on `(session_id, question_id)`.
  - **Mode C (Custom Practice)**: Filter by one or multiple subjects, specific lectures, difficulty (`Easy`, `Medium`, `Hard`), or topic tags; choose question count; shuffle question order; shuffle answer options (`A–D`) while preserving the canonical correct answer; and avoid recently answered questions.
- **Administrator Console & Individual Content/User Management**:
  - Role-protected administrative interface (`zeyadzedan098@gmail.com` protected as primary owner admin) supporting individual creation, editing, and one-by-one deletion of subjects, lectures, question banks, questions, and student quiz sessions, plus user role management (`Student` ↔ `Admin`) and bulk 16-column CSV import/export.

---

## 2. Technology Stack

- **Frontend**: React 19, TypeScript (strict), Tailwind CSS v4, Lucide Icons.
- **Backend & Server Logic**: Node.js + Express (`server.ts`) with bounded self-pruning rate limiters (`src/middleware/rate-limit.ts`), SVG XSS sanitization (`sanitizeSvgDiagram`), and transactional PostgreSQL repository operations (`src/db/repository.ts`).
- **Database & ORM**: Managed PostgreSQL (Cloud SQL / Supabase compatible) with **Drizzle ORM** (`src/db/schema.ts`, `src/db/index.ts`) and version-controlled SQL migrations (`supabase/migrations/0001_initial_schema.sql`).
- **Authentication**: Firebase Authentication (`firebase` + `firebase-admin`) and HMAC-SHA256 local session authentication (`src/middleware/auth.ts`).

---

## 3. Environment Configuration & Setup

### Prerequisites
- **Node.js** v20+ (v22 recommended)
- **PostgreSQL** database (Cloud SQL or Supabase PostgreSQL)

### Required Environment Variables
Copy `.env.example` to `.env` and configure:
1. **`AUTH_SESSION_SECRET`** (**Required**):
   Must be at least 32 characters with high entropy (no default fallback secret is allowed). Generate a secure 64-character hex secret with:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
2. **PostgreSQL Connection Variables**:
   - `SQL_HOST`, `SQL_DB_NAME`, `SQL_USER`, `SQL_PASSWORD` (application runtime pool)
   - `SQL_ADMIN_USER`, `SQL_ADMIN_PASSWORD` (Drizzle schema migrations)
3. **`PASSWORD_RESET_WEBHOOK_URL`** (*Optional*):
   Outbound HTTPS webhook URL to deliver single-use password recovery tokens via your transactional email provider.

### Commands
1. **Install dependencies**:
   ```bash
   npm install
   ```
2. **Start development server (port 3000)**:
   ```bash
   npm run dev
   ```
3. **Run type-checking (`tsc --noEmit`)**:
   ```bash
   npm run lint
   ```
4. **Run unit & security regression tests**:
   ```bash
   npm test
   ```
5. **Build production frontend (`dist/`) and compiled server bundle (`dist/server.js`)**:
   ```bash
   npm run build
   ```
6. **Start production server**:
   ```bash
   npm run start
   # or run the pre-bundled production server:
   npm run start:prod
   ```
