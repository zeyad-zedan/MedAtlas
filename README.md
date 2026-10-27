# MedAtlas MCQ — Medical Education & Examination Platform

MedAtlas MCQ is a full-stack lecture-based multiple-choice question (MCQ) learning platform designed for medical students and medical curriculum administrators.

---

## 1. Project Overview

MedAtlas MCQ organizes medical educational content into a strict academic hierarchy:
**Subject → Lecture → Question Bank → Individual Questions**

Key capabilities implemented in this initial Free Trial release:
- **Student Authentication & Account Isolation**: Email & password registration/login (with scrypt-salted hashing), password recovery, Google Sign-In via Firebase Auth, editable profile display name, and account deletion. Every student's attempts, sessions, and bookmarks are strictly isolated to their unique authenticated `uid`.
- **Three Practice & Assessment Modes**:
  - **Mode A (Study Mode)**: Immediate feedback after submitting each question, showing the correct answer, primary synthesis explanation, and individual rationales for Options A, B, C, and D.
  - **Mode B (Exam Mode)**: Server-enforced timed exam simulation. Correct answers and explanations are stripped on the server during active exams so they are never leaked in network payloads or DOM elements prior to final submission.
  - **Mode C (Custom Practice)**: Filter by one or multiple subjects, specific lectures, difficulty (`Easy`, `Medium`, `Hard`), or topic tags; choose question count; shuffle question order; shuffle answer options (`A–D`) while preserving the canonical correct answer; and avoid recently answered questions.
- **Student Dashboard & Transparent Analytics**: Real database metrics tracking completed attempts, **unique questions completed vs. total answers submitted**, subject and lecture accuracy, attempt history with immutable question snapshots, and **small-sample guarded weak-topic analysis** (topics with `< 3` attempts are marked `Insufficient Sample` rather than mislabeling a student as weak).
- **Administrator Console & Bulk CSV Import/Export**: Role-protected administrative interface for managing subjects, lectures, and questions (with student preview and versioned edits that never corrupt historical exam scores), plus a 16-column CSV bulk validator, importer, and full CSV backup exporter.

---

## 2. Technology Stack

- **Frontend**: React 19, TypeScript (strict), Tailwind CSS v4, Lucide Icons.
- **Backend & Server Logic**: Node.js + Express (`server.ts`) providing server-side authentication verification, exam answer stripping, idempotent exam grading, and RBAC enforcement.
- **Database & ORM**: Managed PostgreSQL (Cloud SQL / Supabase compatible) with **Drizzle ORM** (`src/db/schema.ts`, `src/db/index.ts`) and version-controlled SQL migrations (`supabase/migrations/0001_initial_schema.sql`).
- **Authentication**: Firebase Authentication (`firebase` + `firebase-admin`) alongside scrypt-salted Email/Password server session authentication.

---

## 3. Folder Structure

```text
/
├── .env.example                           # Environment variable template (no secrets)
├── firebase-applet-config.json            # Firebase Client & Admin project configuration
├── package.json                           # Scripts and dependencies
├── server.ts                              # Express API server & server-side exam grading
├── supabase/
│   └── migrations/
│       └── 0001_initial_schema.sql        # Version-controlled PostgreSQL DDL, indexes & RLS
└── src/
    ├── App.tsx                            # Root application router & workspace layout
    ├── index.css                          # Academic typography & Tailwind CSS setup
    ├── components/
    │   ├── PublicLanding.tsx              # Public landing page, auth modal & legal dialogs
    │   ├── McqSessionPlayer.tsx           # Study Mode, Timed Exam Mode & Custom MCQ player
    │   ├── StudentViews.tsx               # Dashboard, Subjects/Lectures, Bookmarks, History, Profile
    │   └── AdminConsole.tsx               # Admin CRUD, Student Preview & Bulk CSV Import/Export
    ├── db/
    │   ├── drizzle.config.ts              # Drizzle Kit migration config
    │   ├── index.ts                       # PostgreSQL connection pool (Object Method)
    │   ├── schema.ts                      # Normalized PostgreSQL tables & relations
    │   ├── seed-data.ts                   # Foundational medical subjects, lectures & MCQs
    │   └── repository.ts                  # Sanitized two-layer database queries
    ├── lib/
    │   ├── api.ts                         # Client API wrapper (in-memory token storage)
    │   ├── firebase.ts                    # Firebase client SDK setup
    │   ├── firebase-admin.ts              # Firebase Admin token verification setup
    │   ├── mcq-engine.ts                  # Pure MCQ scoring, option shuffling & CSV validation
    │   └── mcq-engine.test.ts             # Automated unit test suite (node:test)
    └── middleware/
        └── auth.ts                        # Server-side authentication & password hashing
```

---

## 4. Prerequisites & Installation Instructions

### Prerequisites
- **Node.js** v20+ (v22 recommended)
- **PostgreSQL** database (Cloud SQL or Supabase PostgreSQL)

### Commands (Run in the project root directory `/`)
1. **Install dependencies**:
   ```bash
   npm install
   ```
2. **Configure environment variables**:
   Copy `.env.example` to `.env` and fill in your PostgreSQL connection parameters (`SQL_HOST`, `SQL_DB_NAME`, `SQL_USER`, `SQL_PASSWORD`, `SQL_ADMIN_USER`, `SQL_ADMIN_PASSWORD`).
3. **Start the development server on port 3000**:
   ```bash
   npm run dev
   ```
4. **Run automated unit tests**:
   ```bash
   npm test
   ```
5. **Type-check the project**:
   ```bash
   npm run lint
   ```
6. **Build for production**:
   ```bash
   npm run build
   ```

---

## 5. Administrator Provisioning

Public student registration (`POST /api/auth/register`) **strictly assigns the `'student'` role** and never allows a user to elevate their own role via browser requests or profile edits.

To provision an administrator:
1. **Via Environment Bootstrap**: Set `INITIAL_ADMIN_EMAIL="your-email@domain.com"` in `.env`. When that verified account signs in, the server automatically assigns `role = 'admin'`.
2. **Via Controlled Database Operation**: Run the following SQL command using an administrative database client:
   ```sql
   UPDATE public.users SET role = 'admin', updated_at = NOW() WHERE email = 'your-email@domain.com';
   ```
3. **Trial Demo Administrator**: In the trial environment, you can click **"Explore Admin Console"** on the landing page or **"Switch to Admin Demo"** in the sidebar to inspect the pre-provisioned administrator account (`admin.demo@medatlas.edu`).

---

## 6. Bulk Question CSV Format

Administrators can download the official sample CSV template directly inside **Admin Console → Bulk CSV Import & Export**. The CSV uses 16 columns:

| Column | Required | Description |
| :--- | :--- | :--- |
| `subject` | Yes | Subject title (created automatically if new) |
| `lecture` | Yes | Lecture title under the parent subject |
| `question_text` | Yes | Clinical vignette or question stem (min 10 characters) |
| `option_a` | Yes | Choice A text |
| `option_b` | Yes | Choice B text |
| `option_c` | Yes | Choice C text |
| `option_d` | Yes | Choice D text |
| `correct_answer` | Yes | Single letter: `A`, `B`, `C`, or `D` |
| `explanation` | Yes | Core synthesis explanation for the correct answer |
| `explanation_a` | No | Specific rationale for Option A |
| `explanation_b` | No | Specific rationale for Option B |
| `explanation_c` | No | Specific rationale for Option C |
| `explanation_d` | No | Specific rationale for Option D |
| `difficulty` | No | `Easy`, `Medium`, or `Hard` (defaults to `Medium`) |
| `tags` | No | Comma-separated topic tags (e.g., `"Collagen,Genetics"`) |
| `status` | No | `published`, `draft`, or `archived` (defaults to `published`) |

---

## 7. Future Premium Subscription Architecture Plan

During the current 2-month **Free Trial**, all published content is unlocked for every registered student (`subscription_tier = 'free_trial'`). The codebase and database schema already include clean architectural boundaries so paid subscriptions can be activated later without rewriting the application:

1. **Database Entitlement Columns (Already Present)**:
   - `users.subscription_tier` (`'free_trial' | 'free' | 'premium_monthly' | 'premium_annual'`)
   - `users.subscription_status` (`'active' | 'trialing' | 'expired' | 'canceled'`)
   - `users.subscription_expires_at` (`TIMESTAMP`)
   - `question_banks.is_premium` (`BOOLEAN`)
2. **Where Server-Side Entitlement Checks Will Be Introduced**:
   - In `src/db/repository.ts` inside `createPracticeOrExamSession`: when `PREMIUM_ENFORCEMENT_ENABLED=true`, check whether the requested lecture/bank has `is_premium = true` and verify `user.subscriptionStatus === 'active' && user.subscriptionExpiresAt > NOW()` on the server.
3. **Webhook & Payment Provider Integration**:
   - Add a dedicated server-side webhook route (`POST /api/webhooks/billing`) that verifies cryptographic provider signatures, records idempotent payment events, updates `subscription_tier` and `subscription_expires_at`, and handles renewals, failed payments, and refunds purely on the server.
