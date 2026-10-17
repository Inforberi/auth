-- Offline, database-owner operation. Run only after restore, with every Auth writer stopped.
-- BEGIN/COMMIT are owned here so direct psql execution cannot partially invalidate credentials.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
  IF current_user <> session_user OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='auth' AND c.relname='users' AND c.relowner=current_user::regrole::oid
  ) THEN
    RAISE EXCEPTION 'auth restore invalidation requires the schema table owner without SET ROLE';
  END IF;
  -- Same exclusive Access snapshot lock as administrator/status/settings mutations.
  IF NOT pg_try_advisory_xact_lock(734013981) THEN
    RAISE EXCEPTION 'Auth writers are still active; keep traffic closed';
  END IF;
END;
$$;

LOCK TABLE auth.users, auth.sessions, auth.refresh_families, auth.refresh_tokens,
  auth.email_verifications, auth.email_verification_outbox, auth.password_resets, auth.password_reset_outbox,
  auth.mfa_totp, auth.mfa_recovery_codes, auth.mfa_enrollments, auth.mfa_login_challenges,
  auth.mfa_recovery_requests, auth.mfa_recovery_outbox, auth.email_bindings,
  auth.email_login_challenges, auth.email_login_outbox, auth.email_changes, auth.email_change_outbox,
  auth.account_invitations, auth.invitation_outbox, auth.temporary_password_credentials,
  auth.temporary_password_tokens, auth.restore_audit IN ACCESS EXCLUSIVE MODE;

UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL;
UPDATE auth.refresh_families SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL;
-- Keep refresh history and audit; revoked families can never rotate again.
DELETE FROM auth.email_verifications;
DELETE FROM auth.password_resets;
DELETE FROM auth.mfa_enrollments;
DELETE FROM auth.mfa_login_challenges; -- Also removes pending/approved recovery requests.
DELETE FROM auth.mfa_recovery_codes;
-- TOTP accepts a +/-1 step window: never replay a code from the restored/current window.
UPDATE auth.mfa_totp SET last_step=GREATEST(last_step,floor(extract(epoch FROM clock_timestamp())/30)::bigint+1);
UPDATE auth.mfa_recovery_outbox SET attempts=5,failed_at=clock_timestamp(),lease=NULL,lease_until=NULL
  WHERE failed_at IS NULL;
DELETE FROM auth.email_bindings;
DELETE FROM auth.email_login_challenges;
DELETE FROM auth.email_change_outbox;
UPDATE auth.email_changes SET state='cancelled',recovery_digest=NULL,recovery_payload=NULL,
  recovery_ttl_seconds=NULL,recovery_version=NULL,recovery_expires_at=NULL
  WHERE state IN ('pending','completed','reported');
DELETE FROM auth.account_invitations;
DELETE FROM auth.temporary_password_credentials; -- Also removes their continuation tokens.

WITH invalidated AS (
  UPDATE auth.users SET auth_version=auth_version+1 RETURNING 1
)
INSERT INTO auth.restore_audit(operator_oid,operator_name,database_name,users_invalidated)
  SELECT session_user::regrole::oid,session_user,current_database(),count(*) FROM invalidated;
COMMIT;
