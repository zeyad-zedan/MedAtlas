# MedAtlas MCQ — Medical Education & Examination Platform

MedAtlas MCQ is a full-stack lecture-based multiple-choice question (MCQ) learning platform designed for medical students and medical curriculum administrators.

---

## 1. Project Overview

MedAtlas MCQ organizes medical educational content into a strict academic hierarchy:
**Subject → Lecture → Question Bank → Individual Questions**

Key capabilities and security controls implemented in this release:
- **Hardened Authentication, Admin Provisioning & Account Isolation**:
  - **Authoritative Password Credential**: PostgreSQL `users.password_hash` (scrypt-salted async hashing, strictly bounded to `8..128` characters and `<= 512` UTF-8 bytes before any scrypt operation) is the authoritative password credential for email/password sign-in.
  - **Synchronized Password Changes & Recovery**: Authenticated password changes (`POST /api/auth/change-password`) and password linking (`POST /api/auth/link-password`) synchronize with Firebase Authentication when a user has a mapped `firebase_uid` or provider identity, failing closed (`503`) if a required provider update fails so stale provider credentials can never overwrite a newer local password.
  - **Dedicated Session Revocation (`sessions_revoked_at`)**: Session revocation checks use `users.sessions_revoked_at` (never generic `users.updated_at`), ensuring ordinary profile edits (`displayName`, `preferences`) never invalidate active sessions even when `token_version > 1`, while password changes, password resets, logouts, role changes, and account deletions immediately revoke prior sessions.
  - **Fail-Closed Firebase Token Revocation**: `verifyFirebaseIdTokenWithRevocation` and `requireAuth` fail closed (`401`/`403`/`503`) on revoked, disabled, expired, network timeout, permission, or unknown Firebase errors. Narrow fallback when local ADC credentials are absent (`app/invalid-credential`) requires verification against PostgreSQL session/tombstone state and live Identity Toolkit `accounts:lookup`.
  - **Permanent Tombstones & Identity Mapping**: `users` and `deleted_accounts` explicitly track `firebase_uid`. Account deletion removes or disables the Firebase identity (recording `remote_cleanup_status = 'completed' | 'pending_retry'` with `reconcilePendingDeletedAccounts()` retry support) and preserves `deleted_accounts` rows permanently across re-registrations so deleted `uid` and `firebase_uid` values can never be resurrected or used for credential fallback.
- **Firebase-Native Link-Based Password Recovery**:
  - **End-to-End Synchronization**: Password reset requests (`POST /api/auth/forgot-password`) record `users.pending_recovery_at` and dispatch reset links via Firebase Identity Toolkit (`accounts:sendOobCode`) without silent fallback when `continueUrl` is rejected.
  - **Dual Action-Handler & Hosted-Reset Support**: Completing a reset via MedAtlas (`POST /api/auth/reset-password` with `oobCode` or a pasted reset link) performs a 2-phase verification and atomic database update. If a user completes the reset directly on Firebase's hosted action page (`/__/auth/action`), the active `pending_recovery_at` window immediately invalidates the old local password and synchronizes the new Firebase password into PostgreSQL (revoking prior sessions) on first sign-in.
  - **Exact Recovery Origin Allowlist**: Broad wildcard suffix matching (`*.ai.studio`, `*.run.app`) is removed. Only exact allowlisted HTTPS origins (`https://medatlas.ai.studio`, the specific MedAtlas dev/preview Cloud Run URLs, and origins in `APP_URL` / `ALLOWED_RECOVERY_ORIGINS`) are accepted, with `http://localhost` permitted only outside production.
- **Shared PostgreSQL Rate Limiting & DoS Hardening**:
  - Authentication and password mutation endpoints use a shared PostgreSQL rate-limit store (`rate_limit_buckets`) with independent per-IP, per-account/email, and combined IP+email rules, anti-churn capacity protection (preventing single-hit `count === 1` key floods from evicting active `count > 1` blocks), and automatic in-memory fallback.
  - Default JSON body parsing is restricted to `64kb` globally, with `5mb` scoped exclusively to authenticated administrator CSV import routes (`/api/admin/import/preview` and `/api/admin/import/execute`).
- **Three Practice & Assessment Modes**:
  - **Mode A (Study Mode)**: Immediate feedback after submitting each question, showing the correct answer, primary synthesis explanation, and individual rationales for Options A, B, C, and D.
  - **Mode B (Exam Mode)**: Server-enforced timed exam simulation. Correct answers and explanations are stripped on the server during active exams. Authoritative exam deadlines (`started_at + time_limit_seconds`) are enforced on the server, and `completeExamSession` executes atomically inside a PostgreSQL transaction with `FOR UPDATE` row locking and a unique index (`uq_session_question_attempt`) on `(session_id, question_id)`.
  - **Mode C (Custom Practice)**: Filter by subjects, lectures, difficulty (`Easy`, `Medium`, `Hard`), or tags; shuffle questions/options (`A–D`) with key preservation; and avoid recently answered questions.
- **Strict AST-Based SVG Sanitization**:
  - Question and bookmark SVG diagrams are parsed and sanitized through a strict tag/attribute/CSS allowlist (`sanitizeSvgDiagram`) that decodes HTML/XML entities and strips `<script>`, `<foreignObject>`, event handlers, external references, and dangerous URIs.

---

## 2. Technology Stack

- **Frontend**: React 19, TypeScript (strict), Tailwind CSS v4, Lucide Icons.
- **Backend & Server Logic**: Node.js + Express (`server.ts`) compiled via `esbuild` to `dist/server.js` for production.
- **Database & ORM**: Managed PostgreSQL (Cloud SQL / Supabase compatible) with **Drizzle ORM** (`src/db/schema.ts`, `src/db/index.ts`, `src/db/repository.ts`, `drizzle/0001_security_remediation.sql`).
- **Authentication & Recovery**: Firebase Authentication (`firebase` + `firebase-admin`, Identity Toolkit) and HMAC-SHA256 local session authentication (`src/middleware/auth.ts`).

---

## 3. Production Environment Configuration & Firebase Console Setup

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
| `APP_URL` | **Runtime** | Canonical HTTPS origin of the deployed application (defaults to `https://medatlas.ai.studio`). Must not contain paths, query strings, or credentials. |
| `ALLOWED_RECOVERY_ORIGINS` | **Optional** | Comma-separated list of exact additional HTTPS origins permitted in password recovery links (no wildcards). |
| `TRUST_PROXY_HOPS` | **Optional** | Number of reverse-proxy hops to trust for rate-limiting IP extraction (`1` by default on Cloud Run/production, `0`/`false` when direct). |
| `PORT` | **Optional** | HTTP server listening port (defaults to `3000`). |

### Required Manual Firebase Console Configuration

To ensure Firebase password-reset emails deliver users directly to the MedAtlas reset handler (or allow authorized `continueUrl` redirects):
1. Open **Firebase Console** (`gen-lang-client-0798026854`) → **Authentication** → **Settings** → **Authorized domains** and verify the following domains are listed:
   - `medatlas.ai.studio`
   - `ais-dev-5mhsafvm6orewiuxge6ast-323922691346.europe-west1.run.app`
   - `ais-pre-5mhsafvm6orewiuxge6ast-323922691346.europe-west1.run.app`
2. Open **Firebase Console** → **Authentication** → **Templates** → **Password reset** → click **Customize action URL** and set the custom Action URL to:
   - `https://medatlas.ai.studio/?mode=resetPassword`
   *(When configured as the custom Action URL, Firebase appends `&oobCode=<code...>&apiKey=<...>` directly to `https://medatlas.ai.studio/?mode=resetPassword`, which `PublicLanding.tsx` automatically detects, pre-fills, and strips from the browser URL bar. Even if the default Firebase hosted `/__/auth/action` page is used instead, MedAtlas tracks `pending_recovery_at`, immediately invalidates the old local password, and synchronizes the new password on sign-in.)*

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


