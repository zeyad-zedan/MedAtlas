-- Production-compatible idempotent migration for MedAtlas MCQ Security Remediation
-- 1. Add explicit provider mapping, password update watermark, recovery window, and dedicated session revocation timestamp to users
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "firebase_uid" text;
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "password_updated_at" timestamp;
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "pending_recovery_at" timestamp;
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "sessions_revoked_at" timestamp;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_firebase_uid_unique'
  ) THEN
    ALTER TABLE "users" ADD CONSTRAINT "users_firebase_uid_unique" UNIQUE ("firebase_uid");
  END IF;
END $$;

-- Backfill firebase_uid for existing Firebase/linked accounts whose primary uid is already a Firebase UID
UPDATE "users"
SET "firebase_uid" = "uid"
WHERE "firebase_uid" IS NULL
  AND "auth_provider" IN ('firebase', 'both', 'linked')
  AND "uid" NOT LIKE 'usr_%';

-- Backfill sessions_revoked_at for historical rows that had already incremented token_version > 1
UPDATE "users"
SET "sessions_revoked_at" = "updated_at"
WHERE "sessions_revoked_at" IS NULL
  AND "token_version" > 1;

-- 2. Enhance deleted_accounts tombstones with explicit firebase_uid and remote cleanup reconciliation tracking
ALTER TABLE "deleted_accounts" ADD COLUMN IF NOT EXISTS "firebase_uid" text;
ALTER TABLE "deleted_accounts" ADD COLUMN IF NOT EXISTS "remote_cleanup_status" text NOT NULL DEFAULT 'completed';
ALTER TABLE "deleted_accounts" ADD COLUMN IF NOT EXISTS "last_cleanup_error" text;

-- 3. Create shared multi-instance rate_limit_buckets table
CREATE TABLE IF NOT EXISTS "rate_limit_buckets" (
  "key" text PRIMARY KEY NOT NULL,
  "scope" text NOT NULL,
  "count" integer NOT NULL DEFAULT 1,
  "reset_at" timestamp NOT NULL,
  "updated_at" timestamp NOT NULL DEFAULT now()
);
