# MedAtlas MCQ — Medical Education & Examination Platform

MedAtlas MCQ is a full-stack lecture-based multiple-choice question (MCQ) learning platform designed for medical students and medical curriculum administrators.

---

## 1. Project Overview

MedAtlas MCQ organizes medical educational content into a strict academic hierarchy:
**Subject → Lecture → Question Bank → Individual Questions**

Key capabilities and security controls implemented in this release:
- **Hardened Authentication, Admin Provisioning & Account Isolation**:
  - Local Email & Password authentication uses scrypt-salted password hashes and HMAC-SHA256 signed session tokens (`medatlas.v1.<payload>.<sig>`) bound to a database-backed `token_version`, revocation watermark, and an externally configured high-entropy `AUTH_SESSION_SECRET` (minimum 32 characters; server fails fast on startup if missing or weak).
  - Local registration (`POST /api/auth/register`) always creates accounts with `role = 'student'` and `email_verified = false`. Unauthenticated local registration cannot grant `admin` privileges even if the supplied email matches `OWNER_ADMIN_EMAIL`.
  - The initial owner administrator (`zeyadzedan098@gmail.com`) is provisioned only through verified Firebase Authentication (`email_verified === true`) serialized with a PostgreSQL transaction advisory lock (`pg_advisory_xact_lock`), or via role promotion by an existing database-verified administrator (`PUT /api/admin/users/:uid/role`).
  - Both local and Firebase authentication paths in `requireAuth` check Firebase token revocation (`verifyIdToken(token, true)`), PostgreSQL `deleted_accounts` tombstones, `users.account_status === 'active'`, and per-user session revocation timestamps so logout, password change, password reset, account deletion, and suspension immediately invalidate active tokens.
- **Account-Type-Aware Password Recovery**:
  - **Firebase-backed accounts (`auth_provider = 'firebase'`)**: `POST /api/auth/forgot-password` dispatches a single password-reset email via Firebase Authentication (`accounts:sendOobCode`) and creates no unused database reset rows.
  - **Local-only email/password accounts (`auth_provider = 'local'`)**: Generates a single-use 32-byte token (stored only as a SHA-256 hash in `password_reset_tokens` with a 15-minute expiration) and delivers the reset link via `LOCAL_PASSWORD_RESET_WEBHOOK_URL`. If no local email delivery transport is configured, the API fails honestly with `503 Service Unavailable` explaining that local reset email delivery is not configured, rather than falsely claiming an email was sent.
  - **Linked accounts (`auth_provider = 'both'`)**: Completing a password reset via either a Firebase `oobCode` or a local single-use token updates the PostgreSQL `password_hash`, increments `users.token_version`, and revokes prior sessions so old local passwords cannot remain active after a reset.
  - **Trusted Origin Validation**: Any caller-supplied recovery `origin` is validated against `APP_URL` and `ALLOWED_RECOVERY_ORIGINS`; untrusted origins are rejected with `400 Bad Request`.
- **Three Practice & Assessment Modes**:
  - **Mode A (Study Mode)**: Immediate feedback after submitting each question, showing the correct answer, primary synthesis explanation, and individual rationales for Options A, B, C, and D.
  - **Mode B (Exam Mode)**: Server-enforced timed exam simulation. Correct answers and explanations are stripped on the server during active exams. Authoritative exam deadlines (`started_at + time_limit_seconds`) are enforced on the server, and `completeExamSession` executes atomically inside a PostgreSQL transaction with `FOR UPDATE` row locking and a unique index (`uq_session_question_attempt`) on `(session_id, question_id)`.
  - **Mode C (Custom Practice)**: Filter by subjects, lectures, difficulty (`Easy`, `Medium`, `Hard`), or tags; shuffle questions/options (`A–D`) with key preservation; and avoid recently answered questions.
- **Strict AST-Based SVG Sanitization & Proxy-Safe Rate Limiting**:
  - Question and bookmark SVG diagrams are parsed and sanitized through a strict tag/attribute/CSS allowlist (`sanitizeSvgDiagram`) that decodes HTML/XML entities and strips `<script>`, `<foreignObject>`, event handlers, external references, and dangerous URIs.
  - Rate limiters use Express's configured `trust proxy` hop count (`TRUST_PROXY_HOPS`) and never trust raw client-supplied `X-Forwarded-For` headers directly.

---

## 2. Technology Stack

- **Frontend**: React 19, TypeScript (strict), Tailwind CSS v4, Lucide Icons.
- **Backend & Server Logic**: Node.js + Express (`server.ts`) compiled via `esbuild` to `dist/server.js` for production.
- **Database & ORM**: Managed PostgreSQL (Cloud SQL / Supabase compatible) with **Drizzle ORM** (`src/db/schema.ts`, `src/db/index.ts`, `src/db/repository.ts`).
- **Authentication**: Firebase Authentication (`firebase` + `firebase-admin`) and HMAC-SHA256 local session authentication (`src/middleware/auth.ts`).

---

## 3. Production Environment Configuration & Deployment Instructions

### Required & Optional Environment Variables

| Variable | Required | Purpose |
| :--- | :--- | :--- |
| `AUTH_SESSION_SECRET` | **Yes** | High-entropy secret (minimum 32 characters, >= 10 distinct characters) used to sign and verify HMAC-SHA256 local session tokens (`medatlas.v1.<payload>.<sig>`). Loaded automatically via `dotenv/config` before validation. Generate via: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `SQL_HOST` | **Yes** | Cloud SQL Unix socket path (`/cloudsql/<instance-connection-name>`) or PostgreSQL hostname/IP. |
| `SQL_DB_NAME` | **Yes** | PostgreSQL database name (e.g., `postgres`). |
| `SQL_USER` | **Yes** | PostgreSQL runtime application user account. |
| `SQL_PASSWORD` | **Yes** | Password for `SQL_USER`. |
| `SQL_ADMIN_USER` | **Migrations** | PostgreSQL administrative user used by Drizzle Kit when applying schema migrations. |
| `SQL_ADMIN_PASSWORD` | **Migrations** | Password for `SQL_ADMIN_USER`. |
| `APP_URL` | **Runtime** | Public base URL of the deployed application. Used as the default trusted origin for password recovery links. |
| `LOCAL_PASSWORD_RESET_WEBHOOK_URL` | **Optional** | Outbound HTTPS webhook endpoint receiving `{ to, displayName, resetUrl, expiresInMinutes }` to deliver password reset emails for local-only email/password accounts (`auth_provider = 'local'`). |
| `ALLOWED_RECOVERY_ORIGINS` | **Optional** | Comma-separated list of additional trusted origins permitted in password recovery links. |
| `TRUST_PROXY_HOPS` | **Optional** | Number of reverse-proxy hops to trust for rate-limiting IP extraction (`1` by default on Cloud Run/production, `0`/`false` when direct). |
| `PORT` | **Optional** | HTTP server listening port (defaults to `3000`). |

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
6. **Start compiled production server (`NODE_ENV=production node dist/server.js`)**:
   ```bash
   npm run start
   ```


