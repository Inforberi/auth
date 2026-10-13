CREATE SCHEMA auth;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;

CREATE TABLE auth.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  status TEXT NOT NULL DEFAULT 'active'
    CONSTRAINT users_status_check CHECK (status IN ('pending', 'active', 'blocked')),
  auth_version BIGINT NOT NULL DEFAULT 1 CHECK (auth_version > 0),
  access_version BIGINT NOT NULL DEFAULT 1 CHECK (access_version > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  email_reuse_blocked BOOLEAN NOT NULL DEFAULT false,
  email_released_at TIMESTAMPTZ,
  CHECK (NOT email_reuse_blocked OR deleted_at IS NOT NULL),
  CHECK (email_released_at IS NULL OR (deleted_at IS NOT NULL AND NOT email_reuse_blocked AND email_released_at >= deleted_at)),
  CONSTRAINT users_deleted_status_check CHECK (deleted_at IS NULL OR status = 'blocked'),
  CHECK (updated_at >= created_at),
  CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);
CREATE INDEX users_email_release_due ON auth.users(deleted_at,id)
  WHERE deleted_at IS NOT NULL AND NOT email_reuse_blocked AND email_released_at IS NULL;

CREATE TABLE auth.roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key TEXT COLLATE "C" NOT NULL UNIQUE CHECK (octet_length(key) BETWEEN 1 AND 96 AND key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
  name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 200 AND btrim(name) <> ''),
  description TEXT NOT NULL DEFAULT '' CHECK (octet_length(description) <= 2000),
  system BOOLEAN NOT NULL DEFAULT false,
  version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK (system = (key = 'super_admin'))
);

CREATE TABLE auth.role_permissions (
  role_id UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
  permission_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(permission_key) BETWEEN 1 AND 96 AND permission_key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
  PRIMARY KEY (role_id, permission_key)
);

CREATE TABLE auth.user_roles (
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES auth.roles(id),
  PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_roles_by_role ON auth.user_roles(role_id,user_id);

CREATE TABLE auth.access_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  target_id UUID REFERENCES auth.users(id),
  role_id UUID NOT NULL REFERENCES auth.roles(id),
  event TEXT NOT NULL CHECK (event IN ('role_created','role_updated','role_granted','role_revoked')),
  role_version BIGINT NOT NULL CHECK (role_version > 0),
  access_version BIGINT CHECK (access_version > 0),
  role_snapshot JSONB NOT NULL CHECK (jsonb_typeof(role_snapshot)='object' AND octet_length(role_snapshot::text)<=32768),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK ((target_id IS NOT NULL) = (event IN ('role_granted','role_revoked'))),
  CHECK ((access_version IS NOT NULL) = (target_id IS NOT NULL))
);
CREATE INDEX access_audit_retention ON auth.access_audit(created_at,id);

CREATE TABLE auth.linked_identities (
  issuer TEXT COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 512 AND btrim(issuer) <> ''),
  subject TEXT COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255 AND btrim(subject) <> ''),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT linked_identities_key PRIMARY KEY (issuer, subject),
  CONSTRAINT linked_identities_provider_owner_key UNIQUE (user_id, issuer)
);

CREATE TABLE auth.identity_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id),
  event TEXT NOT NULL CHECK (event IN ('identity_created','identity_linked','identity_unlinked')),
  auth_version BIGINT NOT NULL CHECK (auth_version > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX identity_audit_retention ON auth.identity_audit(created_at,id);

-- Deleted owners retain contacts until retention release; blocked owners are not released.
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
CREATE INDEX email_verifications_expiry ON auth.email_verifications(expires_at,digest);
CREATE INDEX email_verification_outbox_expiry ON auth.email_verification_outbox(expires_at,id);
CREATE INDEX email_verification_outbox_exhausted ON auth.email_verification_outbox(lease_until NULLS FIRST,id) WHERE attempts>=5;

CREATE TABLE auth.email_verification_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('email_verification_issued', 'email_verified')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.mfa_totp (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  secret BYTEA NOT NULL CHECK (octet_length(secret) BETWEEN 48 AND 512),
  last_step BIGINT NOT NULL CHECK (last_step >= 0),
  enabled_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE auth.mfa_enrollments (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  digest TEXT NOT NULL UNIQUE CHECK (digest ~ '^[a-f0-9]{64}$'),
  auth_version BIGINT NOT NULL CHECK (auth_version > 0),
  session_hash TEXT NOT NULL CHECK (session_hash ~ '^[a-f0-9]{64}$'),
  purpose TEXT NOT NULL DEFAULT 'enroll' CHECK (purpose IN ('enroll','replace')),
  secret BYTEA NOT NULL CHECK (octet_length(secret) BETWEEN 48 AND 512),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at > created_at AND expires_at <= created_at+interval '10 minutes')
);
CREATE INDEX mfa_enrollments_expiry ON auth.mfa_enrollments(expires_at,user_id);

CREATE TABLE auth.mfa_login_challenges (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  digest TEXT NOT NULL UNIQUE CHECK (digest ~ '^[a-f0-9]{64}$'),
  binding_hash TEXT NOT NULL CHECK (binding_hash ~ '^[a-f0-9]{64}$'),
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  primary_method TEXT NOT NULL CHECK (primary_method IN ('password','oidc','emailotp')),
  primary_reference TEXT NOT NULL CHECK (octet_length(primary_reference) BETWEEN 1 AND 1024),
  primary_issuer TEXT NOT NULL CHECK (octet_length(primary_issuer)<=512),
  primary_verified_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
  CHECK (primary_verified_at<=created_at)
);
CREATE INDEX mfa_login_challenges_expiry ON auth.mfa_login_challenges(expires_at,user_id);

CREATE TABLE auth.mfa_recovery_codes (
  user_id UUID NOT NULL REFERENCES auth.mfa_totp(user_id) ON DELETE CASCADE,
  digest TEXT NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (user_id,digest)
);

CREATE TABLE auth.mfa_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id),
  event TEXT NOT NULL CHECK (event IN ('enrollment_started','totp_enabled','totp_verified','recovery_used','login_challenge_started','mfa_login_completed','mfa_step_up','totp_disabled','totp_replaced','recovery_regenerated')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX mfa_audit_retention ON auth.mfa_audit(created_at,id);

CREATE TABLE auth.sessions (
  id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  password_verified_at TIMESTAMPTZ,
  primary_method TEXT CHECK (primary_method IN ('password','oidc','emailotp')),
  primary_verified_at TIMESTAMPTZ,
  mfa_verified_at TIMESTAMPTZ,
  user_agent TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  CHECK (created_at<expires_at AND expires_at<=absolute_expires_at),
  CHECK ((primary_method IS NULL)=(primary_verified_at IS NULL)),
  CHECK (mfa_verified_at IS NULL OR (primary_verified_at IS NOT NULL
    AND primary_verified_at<=mfa_verified_at AND mfa_verified_at<absolute_expires_at))
);
CREATE INDEX sessions_owner ON auth.sessions(user_id,created_at DESC,id DESC);
CREATE INDEX sessions_retention_due ON auth.sessions(LEAST(revoked_at,expires_at,absolute_expires_at),id);

CREATE TABLE auth.email_login_challenges (
  digest TEXT PRIMARY KEY CHECK (digest ~ '^[a-f0-9]{64}$'),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  email_id UUID NOT NULL,
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  verifier TEXT NOT NULL CHECK (verifier ~ '^[a-f0-9]{64}$'),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at),
  FOREIGN KEY (user_id,email_id) REFERENCES auth.user_emails(user_id,id) ON DELETE CASCADE
);
CREATE INDEX email_login_challenges_expiry ON auth.email_login_challenges(expires_at,digest);

CREATE TABLE auth.email_login_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  digest TEXT NOT NULL UNIQUE REFERENCES auth.email_login_challenges(digest) ON DELETE CASCADE,
  payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 28 AND 131072),
  expires_at TIMESTAMPTZ NOT NULL,
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  lease UUID,
  lease_until TIMESTAMPTZ,
  CHECK ((lease IS NULL)=(lease_until IS NULL))
);
CREATE INDEX email_login_outbox_due ON auth.email_login_outbox(available_at,id);
CREATE INDEX email_login_outbox_expiry ON auth.email_login_outbox(expires_at,id);
CREATE INDEX email_login_outbox_exhausted ON auth.email_login_outbox(lease_until NULLS FIRST,id) WHERE attempts>=5;

CREATE TABLE auth.email_login_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id),
  event TEXT NOT NULL CHECK (event IN ('code_issued','code_consumed')),
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_login_audit_retention ON auth.email_login_audit(created_at,id);

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
CREATE INDEX password_resets_expiry ON auth.password_resets(expires_at,digest);
CREATE INDEX password_reset_outbox_expiry ON auth.password_reset_outbox(expires_at,id);
CREATE INDEX password_reset_outbox_exhausted ON auth.password_reset_outbox(lease_until NULLS FIRST,id) WHERE attempts>=5;
CREATE TABLE auth.password_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK (event IN ('password_reset_issued','password_reset','password_changed','sessions_revoked','password_reauthenticated',
    'temporary_password_issued','temporary_password_reissued','temporary_password_started','temporary_password_completed')),
  actor_id UUID REFERENCES auth.users(id),
  auth_version BIGINT CHECK (auth_version IS NULL OR auth_version>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.account_status_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id),
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  previous_status TEXT NOT NULL CHECK (previous_status IN ('pending','active','blocked')),
  new_status TEXT NOT NULL CHECK (new_status IN ('active','blocked')),
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (previous_status<>new_status)
);
CREATE INDEX account_status_audit_owner ON auth.account_status_audit(user_id,created_at DESC,id DESC);

CREATE TABLE auth.account_deletion_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id),
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

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
  recovery_digest TEXT UNIQUE CHECK (recovery_digest ~ '^[a-f0-9]{64}$'),
  recovery_payload BYTEA CHECK (octet_length(recovery_payload) BETWEEN 28 AND 8192),
  recovery_ttl_seconds INTEGER CHECK (recovery_ttl_seconds BETWEEN 60 AND 3600),
  recovery_version BIGINT CHECK (recovery_version>0),
  recovery_expires_at TIMESTAMPTZ,
  completion_payload BYTEA NOT NULL CHECK (octet_length(completion_payload) BETWEEN 28 AND 8192),
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed','cancelled','reported','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at),
  protect_until TIMESTAMPTZ NOT NULL CHECK (protect_until>expires_at),
  FOREIGN KEY (user_id,email_id) REFERENCES auth.user_emails(user_id,id),
  CONSTRAINT email_changes_recovery_prepared CHECK (
    (recovery_digest IS NULL AND recovery_payload IS NULL AND recovery_ttl_seconds IS NULL)
    OR (recovery_digest IS NOT NULL AND recovery_payload IS NOT NULL AND recovery_ttl_seconds IS NOT NULL)),
  CONSTRAINT email_changes_recovery_issued CHECK (
    (recovery_version IS NULL AND recovery_expires_at IS NULL)
    OR (recovery_version IS NOT NULL AND recovery_expires_at IS NOT NULL AND recovery_digest IS NOT NULL)),
  CHECK (old_email<>new_email),
  CHECK (octet_length(new_email::TEXT) BETWEEN 3 AND 255 AND new_email::TEXT=lower(btrim(new_email::TEXT)) AND position('@' IN new_email::TEXT)>1)
);
CREATE UNIQUE INDEX email_changes_pending ON auth.email_changes(user_id) WHERE state='pending';
CREATE INDEX email_changes_expiry ON auth.email_changes(GREATEST(protect_until,recovery_expires_at),id);
CREATE INDEX email_changes_owner ON auth.email_changes(user_id);

CREATE TABLE auth.email_change_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  change_id UUID NOT NULL REFERENCES auth.email_changes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('confirm','notice','completed','recovery')),
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
CREATE INDEX email_change_outbox_exhausted ON auth.email_change_outbox(lease_until NULLS FIRST,id) WHERE attempts>=5;

CREATE TABLE auth.email_change_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id),
  change_id UUID NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('requested','confirmed','cancelled','reported','recovered')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_change_audit_owner ON auth.email_change_audit(user_id,created_at DESC,id DESC);

CREATE INDEX email_verification_audit_retention ON auth.email_verification_audit(created_at,id);
CREATE INDEX password_audit_retention ON auth.password_audit(created_at,id);
CREATE INDEX account_status_audit_retention ON auth.account_status_audit(created_at,id);
CREATE INDEX account_deletion_audit_retention ON auth.account_deletion_audit(created_at,id);
CREATE INDEX email_change_audit_retention ON auth.email_change_audit(created_at,id);

-- Durable actor-scoped command identity; replay never recreates an expired invitation.
CREATE TABLE auth.account_provisions (
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  request_key UUID NOT NULL,
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  user_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE REFERENCES auth.users(id) DEFERRABLE INITIALLY DEFERRED,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at TIMESTAMPTZ CHECK (activated_at IS NULL OR activated_at>=created_at),
  last_invited_at TIMESTAMPTZ,
  invitation_email_id UUID REFERENCES auth.user_emails(id) ON DELETE SET NULL,
  password_change_required BOOLEAN NOT NULL DEFAULT false,
  temporary_password_issued_at TIMESTAMPTZ,
  PRIMARY KEY(actor_id,request_key)
);

CREATE TABLE auth.invitation_reissues (
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  request_key UUID NOT NULL,
  user_id UUID NOT NULL REFERENCES auth.account_provisions(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(actor_id,request_key)
);

CREATE TABLE auth.account_invitations (
  digest TEXT PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  email_id UUID NOT NULL,
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  expires_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY(user_id,email_id) REFERENCES auth.user_emails(user_id,id) ON DELETE CASCADE
);
CREATE INDEX account_invitations_expiry ON auth.account_invitations(expires_at,digest);

CREATE TABLE auth.invitation_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  digest TEXT NOT NULL UNIQUE REFERENCES auth.account_invitations(digest) ON DELETE CASCADE,
  payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 16384),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  lease UUID,
  lease_until TIMESTAMPTZ,
  CHECK ((lease IS NULL) = (lease_until IS NULL))
);
CREATE INDEX invitation_outbox_due ON auth.invitation_outbox(available_at);
CREATE INDEX invitation_outbox_expiry ON auth.invitation_outbox(expires_at,id);
CREATE INDEX invitation_outbox_exhausted ON auth.invitation_outbox(lease_until NULLS FIRST,id) WHERE attempts>=5;

CREATE TABLE auth.invitation_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id),
  actor_id UUID REFERENCES auth.users(id),
  action TEXT NOT NULL CHECK (action IN ('provisioned','reissued','activated')),
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((action IN ('provisioned','reissued')) = (actor_id IS NOT NULL))
);
CREATE INDEX invitation_audit_retention ON auth.invitation_audit(created_at,id);

CREATE TABLE auth.temporary_password_credentials (
  user_id UUID PRIMARY KEY REFERENCES auth.account_provisions(user_id),
  email_id UUID NOT NULL,
  password_hash TEXT NOT NULL CHECK (octet_length(password_hash) BETWEEN 1 AND 1024),
  secret_digest TEXT NOT NULL CHECK (secret_digest ~ '^[0-9a-f]{64}$'),
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  expires_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY(user_id,email_id) REFERENCES auth.user_emails(user_id,id) ON DELETE CASCADE
);
CREATE INDEX temporary_password_credentials_expiry ON auth.temporary_password_credentials(expires_at,user_id);

CREATE TABLE auth.temporary_password_tokens (
  digest TEXT PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.temporary_password_credentials(user_id) ON DELETE CASCADE,
  auth_version BIGINT NOT NULL CHECK (auth_version>0),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX temporary_password_tokens_expiry ON auth.temporary_password_tokens(expires_at,digest);

CREATE TABLE auth.temporary_password_reissues (
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  request_key UUID NOT NULL,
  user_id UUID NOT NULL REFERENCES auth.account_provisions(user_id),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(actor_id,request_key)
);
