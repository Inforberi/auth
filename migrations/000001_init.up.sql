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
