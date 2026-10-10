CREATE SCHEMA auth;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;

CREATE TABLE auth.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  status TEXT NOT NULL DEFAULT 'active'
    CONSTRAINT users_status_check CHECK (status IN ('active', 'blocked')),
  auth_version BIGINT NOT NULL DEFAULT 1 CHECK (auth_version > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  CONSTRAINT users_deleted_status_check CHECK (deleted_at IS NULL OR status = 'blocked'),
  CHECK (updated_at >= created_at),
  CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);

-- Email ownership survives soft deletion; releasing addresses needs explicit policy.
CREATE TABLE auth.user_emails (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  email public.CITEXT NOT NULL,
  verified_at TIMESTAMPTZ,
  verification_sent_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT user_emails_email_key UNIQUE (email),
  CONSTRAINT user_emails_owner_key UNIQUE (user_id, id),
  CONSTRAINT user_emails_format_check CHECK (
    octet_length(email::TEXT) BETWEEN 3 AND 255
    AND email::TEXT = lower(btrim(email::TEXT))
    AND position('@' IN email::TEXT) > 1
  ),
  CHECK (updated_at >= created_at),
  CHECK (verified_at IS NULL OR verified_at >= created_at)
);

CREATE TABLE auth.user_profile (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  first_name VARCHAR(100),
  middle_name VARCHAR(100),
  last_name VARCHAR(100),
  phone_number VARCHAR(20) CHECK (phone_number ~ '^\+[1-9]\d{9,14}$'),
  avatar_url TEXT,
  display_name VARCHAR(100),
  timezone TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (updated_at >= created_at)
);

CREATE TABLE auth.password_credentials (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email_id UUID NOT NULL UNIQUE,
  password_hash TEXT NOT NULL CHECK (
    octet_length(password_hash) BETWEEN 1 AND 1024
    AND password_hash = btrim(password_hash)
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT password_credentials_email_owner_fkey
    FOREIGN KEY (user_id, email_id) REFERENCES auth.user_emails(user_id, id),
  CHECK (updated_at >= created_at)
);

CREATE FUNCTION auth.set_updated_at() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := statement_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER users_updated_at BEFORE UPDATE ON auth.users
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();
CREATE TRIGGER user_emails_updated_at BEFORE UPDATE ON auth.user_emails
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();
CREATE TRIGGER user_profile_updated_at BEFORE UPDATE ON auth.user_profile
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();
CREATE TRIGGER password_credentials_updated_at BEFORE UPDATE ON auth.password_credentials
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();

CREATE TABLE auth.email_verifications (
  digest TEXT PRIMARY KEY CHECK (digest ~ '^[a-f0-9]{64}$'),
  email_id UUID NOT NULL UNIQUE REFERENCES auth.user_emails(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at)
);

CREATE TABLE auth.email_verification_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  digest TEXT NOT NULL UNIQUE REFERENCES auth.email_verifications(digest) ON DELETE CASCADE,
  payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 28 AND 8192),
  expires_at TIMESTAMPTZ NOT NULL,
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  lease UUID,
  lease_until TIMESTAMPTZ,
  CHECK ((lease IS NULL) = (lease_until IS NULL))
);
CREATE INDEX email_verification_outbox_due ON auth.email_verification_outbox(available_at);

CREATE TABLE auth.email_verification_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('email_verification_issued', 'email_verified')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.sessions (
  id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  user_agent TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  CHECK (created_at<expires_at AND expires_at<=absolute_expires_at)
);
CREATE INDEX sessions_owner ON auth.sessions(user_id,created_at DESC,id DESC);

CREATE TABLE auth.password_resets (
  digest TEXT PRIMARY KEY CHECK (digest ~ '^[a-f0-9]{64}$'),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.password_credentials(user_id) ON DELETE CASCADE,
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at)
);
CREATE TABLE auth.password_reset_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  digest TEXT NOT NULL UNIQUE REFERENCES auth.password_resets(digest) ON DELETE CASCADE,
  payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 28 AND 131072),
  expires_at TIMESTAMPTZ NOT NULL,
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  lease UUID,
  lease_until TIMESTAMPTZ,
  CHECK ((lease IS NULL)=(lease_until IS NULL))
);
CREATE INDEX password_reset_outbox_due ON auth.password_reset_outbox(available_at);
CREATE TABLE auth.password_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('password_reset_issued','password_reset','password_changed','sessions_revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.account_status_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id),
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  previous_status TEXT NOT NULL CHECK (previous_status IN ('active','blocked')),
  new_status TEXT NOT NULL CHECK (new_status IN ('active','blocked')),
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (previous_status<>new_status)
);
CREATE INDEX account_status_audit_owner ON auth.account_status_audit(user_id,created_at DESC,id DESC);

CREATE TABLE auth.email_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id),
  email_id UUID NOT NULL,
  old_email public.CITEXT NOT NULL,
  new_email public.CITEXT NOT NULL,
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  session_hash TEXT NOT NULL CHECK (session_hash ~ '^[a-f0-9]{64}$'),
  confirm_digest TEXT NOT NULL UNIQUE CHECK (confirm_digest ~ '^[a-f0-9]{64}$'),
  report_digest TEXT NOT NULL UNIQUE CHECK (report_digest ~ '^[a-f0-9]{64}$'),
  completion_payload BYTEA NOT NULL CHECK (octet_length(completion_payload) BETWEEN 28 AND 8192),
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed','cancelled','reported','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at),
  protect_until TIMESTAMPTZ NOT NULL CHECK (protect_until>expires_at),
  FOREIGN KEY (user_id,email_id) REFERENCES auth.user_emails(user_id,id),
  CHECK (old_email<>new_email),
  CHECK (octet_length(new_email::TEXT) BETWEEN 3 AND 255 AND new_email::TEXT=lower(btrim(new_email::TEXT)) AND position('@' IN new_email::TEXT)>1)
);
CREATE UNIQUE INDEX email_changes_pending ON auth.email_changes(user_id) WHERE state='pending';
CREATE INDEX email_changes_expiry ON auth.email_changes(protect_until);

CREATE TABLE auth.email_change_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  change_id UUID NOT NULL REFERENCES auth.email_changes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('confirm','notice','completed')),
  payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 28 AND 8192),
  expires_at TIMESTAMPTZ NOT NULL,
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  lease UUID,
  lease_until TIMESTAMPTZ,
  UNIQUE(change_id,kind),
  CHECK ((lease IS NULL)=(lease_until IS NULL))
);
CREATE INDEX email_change_outbox_due ON auth.email_change_outbox(available_at);
CREATE INDEX email_change_outbox_expiry ON auth.email_change_outbox(expires_at);

CREATE TABLE auth.email_change_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id),
  change_id UUID NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('requested','confirmed','cancelled','reported')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_change_audit_owner ON auth.email_change_audit(user_id,created_at DESC,id DESC);
