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
- **Firebase-Native Password Recovery**:
  - **Universal Firebase Email Delivery**: All password reset requests (`POST /api/auth/forgot-password`) utilize Firebase Authentication's built-in reset email infrastructure (`accounts:sendOobCode`). Accounts created locally in PostgreSQL are automatically provisioned in Firebase Auth so Google's official email delivery is used for every account with zero custom webhooks.
  - **Account Enumeration Protection**: `POST /api/auth/forgot-password` returns a uniform generic confirmation message whether an account exists or not, preventing email harvesting.
  - **Single-Use Verification & Dual Synchronization**: Password resets completed via Firebase reset links (`oobCode`) or single-use recovery tokens securely update the PostgreSQL `password_hash`, increment `users.token_version`, and record a session revocation watermark to terminate active sessions. Subsequent logins seamlessly synchronize updated Firebase passwords.
  - **Trusted Platform Origin Validation**: Recovery origins are validated against `https://medatlas.ai.studio`, `*.ai.studio`, and `*.run.app` over HTTPS, preventing open-redirect and host-header injection while automatically supporting production, preview, and Cloud Run domains.
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
- **Authentication & Recovery**: Firebase Authentication (`firebase` + `firebase-admin`, Identity Toolkit) and HMAC-SHA256 local session authentication (`src/middleware/auth.ts`).

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
| `APP_URL` | **Runtime** | Public base URL of the deployed application (defaults to `https://medatlas.ai.studio`). |
| `ALLOWED_RECOVERY_ORIGINS` | **Optional** | Comma-separated list of additional trusted origins permitted in password recovery links. |
| `TRUST_PROXY_HOPS` | **Optional** | Number of reverse-proxy hops to trust for rate-limiting IP extraction (`1` by default on Cloud Run/production, `0`/`false` when direct). |
| `PORT` | **Optional** | HTTP server listening port (defaults to `3000`). |

---

## 4. 6-Digit Code Password Recovery & Email Deliverability Guide

### Architecture & Security Guarantees
MedAtlas MCQ implements an in-app 6-digit verification code password recovery architecture:
1. **Cryptographically Secure Random Code**:
   - Generated via `crypto.randomInt(100000, 1000000)` (100000 to 999999).
2. **Keyed HMAC-SHA256 Hash Storage**:
   - Plaintext verification codes are **never** stored in the database.
   - The database stores an HMAC-SHA256 hash keyed with `AUTH_SESSION_SECRET` and salted with the user's permanent unique identifier (`user_uid`). Because 6-digit codes span $10^6$ values, HMAC hashing with a high-entropy secret completely prevents rainbow table precomputation.
3. **Strict Expiration & Single-Use Consumption**:
   - Codes expire automatically after **10 minutes**.
   - Consumption is atomic within a PostgreSQL transaction with `FOR UPDATE` locking.
4. **Brute-Force & Attempt Caps**:
   - Each verification code permits a maximum of **5 failed attempts**. Upon the 5th failed attempt, the code is immediately and permanently deactivated (`consumed_at = NOW()`).
5. **60-Second Resend Cooldown**:
   - Resending a verification code enforces an account-level 60-second cooldown (`429 Too Many Requests`) calculated against `created_at` of the active token.
6. **Account Enumeration Protection**:
   - Requesting a code always returns a uniform generic message whether or not an account exists.
7. **Session Revocation & Credential Synchronization**:
   - Resetting a password increments `users.token_version`, updates server revocation timestamps, updates the PostgreSQL `password_hash`, and updates Firebase Authentication for linked accounts.

---

### Transactional Email Provider Setup

To eliminate spam delivery issues, MedAtlas integrates directly with reputable transactional email providers. Configure **one** of the following in your environment variables:

| Variable | Provider | Documentation & Signup |
| :--- | :--- | :--- |
| `RESEND_API_KEY` | **Resend** (Recommended) | [resend.com](https://resend.com) |
| `POSTMARK_SERVER_TOKEN` | **Postmark** | [postmarkapp.com](https://postmarkapp.com) |
| `SENDGRID_API_KEY` | **SendGrid** | [sendgrid.com](https://sendgrid.com) |
| `EMAIL_FROM` | **Sender Identity** | Must match your verified sending domain (e.g., `MedAtlas Security <security@medatlas.ai.studio>`) |

If no email provider is configured, the server fails safely with an explicit 503 response explaining that email delivery is unconfigured, rather than falsely pretending the code was delivered.

---

### DNS Configuration Guide for `medatlas.ai.studio` (SPF, DKIM, DMARC)

To achieve 100% inbox deliverability and prevent reset emails from landing in spam filters, configure the following DNS records at your domain registrar / DNS provider for `medatlas.ai.studio`:

#### 1. SPF (Sender Policy Framework)
Add or update the TXT record for your domain root (`medatlas.ai.studio`):
```text
Type:  TXT
Host:  @ (or medatlas.ai.studio)
Value: v=spf1 include:resend.com ~all
```
*(If using Postmark: `include:spf.mtasv.net ~all`; if SendGrid: `include:sendgrid.net ~all`).*

#### 2. DKIM (DomainKeys Identified Mail)
In your email provider dashboard (e.g. Resend / Postmark), add your domain `medatlas.ai.studio` and copy the provided CNAME DKIM selector records:
```text
Type:  CNAME
Host:  resend._domainkey.medatlas.ai.studio
Value: dkim.resend.com
```

#### 3. DMARC (Domain-based Message Authentication, Reporting, and Conformance)
Publish a DMARC policy TXT record at the `_dmarc` subdomain:
```text
Type:  TXT
Host:  _dmarc.medatlas.ai.studio
Value: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@medatlas.ai.studio; pct=100; adkim=s; aspf=s
```
- `p=quarantine`: Instructs mailbox providers (Gmail, Outlook, iCloud) to quarantine messages failing SPF/DKIM instead of dropping legitimate mail.
- `adkim=s` & `aspf=s`: Enforces strict DKIM and SPF alignment.
- `pct=100`: Applies to 100% of outbound messages.

---

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



