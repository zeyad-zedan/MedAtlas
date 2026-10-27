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

## 3. Production Environment Configuration & Deployment Instructions

### Prerequisites
- **Node.js** v20+ (v22 recommended)
- **PostgreSQL** database (Cloud SQL or Supabase PostgreSQL)
- **Firebase Authentication** project configuration (`firebase-applet-config.json`, pre-configured for `pivotal-bedrock-c01dl`)

### Required Production Environment Variables

| Variable | Required | Purpose |
| :--- | :--- | :--- |
| `AUTH_SESSION_SECRET` | **Yes** | High-entropy secret (minimum 32 characters, at least 10 distinct characters; 64-character hex recommended) used to sign and verify HMAC-SHA256 local session tokens (`medatlas.v1.<payload>.<sig>`). The server fails fast at startup if missing, short, low-entropy, or set to a placeholder. Generate via: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `SQL_HOST` | **Yes** | Cloud SQL Unix socket path (`/cloudsql/<instance-connection-name>`) or PostgreSQL hostname/IP. |
| `SQL_DB_NAME` | **Yes** | PostgreSQL database name (e.g., `postgres`). |
| `SQL_USER` | **Yes** | PostgreSQL runtime application user account used by the Express server connection pool. |
| `SQL_PASSWORD` | **Yes** | Password for `SQL_USER`. |
| `SQL_ADMIN_USER` | **Migrations** | PostgreSQL administrative user used by Drizzle Kit when applying schema migrations. |
| `SQL_ADMIN_PASSWORD` | **Migrations** | Password for `SQL_ADMIN_USER`. |
| `APP_URL` | **Runtime** | Public base URL of the deployed application (automatically injected by Cloud Run / AI Studio runtime). |
| `PORT` | **Optional** | HTTP server listening port (defaults to `3000`). |

> **Note on Password Recovery (`PASSWORD_RESET_WEBHOOK_URL` Removed):**
> No custom external webhook URL is required. Password recovery uses the configured **Firebase Authentication** service (`firebase-applet-config.json` / Identity Toolkit `accounts:sendOobCode` & `accounts:resetPassword`) together with PostgreSQL single-use SHA-256 hashed tokens (`password_reset_tokens` with 15-minute expiration, bounded rate limiting, and `users.token_version` session invalidation).

### Password-Reset Endpoints & Request Formats

1. **Initiate Password Reset (`POST /api/auth/forgot-password`)**
   - **Rate Limit**: 6 requests per 60 seconds per `IP + email` (`forgotPasswordLimiter`).
   - **Request Body**: `{ "email": "student@medschool.edu" }`
   - **Behavior**: Invalidates any prior unconsumed tokens for the account, stores a new SHA-256 hashed single-use token with a 15-minute expiration in `password_reset_tokens`, triggers Firebase Authentication password-reset email delivery (`accounts:sendOobCode`), and returns an enumeration-safe `200 OK` response:
     `{ "accepted": true, "message": "If an account exists for that email address, a password reset email has been dispatched via Firebase Authentication.", "expiresInMinutes": 15 }`

2. **Complete Password Reset (`POST /api/auth/reset-password`)**
   - **Rate Limit**: 10 requests per 60 seconds per `IP` (`resetPasswordLimiter`).
   - **Request Body**: `{ "token": "<64-char-single-use-token-or-firebase-oobCode>", "newPassword": "<min-8-char-password>" }` (also accepts `"oobCode"` in place of `"token"`).
   - **Behavior**: Rejects unauthenticated `{ email, newPassword }` requests with `400 Bad Request`. Atomically verifies and consumes the single-use token in PostgreSQL (or verifies/consumes the Firebase `oobCode`), updates `users.password_hash` with a salted `scrypt` digest, and increments `users.token_version` so all prior session tokens are immediately revoked.

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

