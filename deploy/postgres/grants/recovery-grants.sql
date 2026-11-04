-- Adapt database identifiers before use; apply as owner after migrations/restore.
-- A database administrator must create auth_recovery_operator NOLOGIN separately
-- and grant membership only to a dedicated operator login, never auth_runtime.
GRANT CONNECT ON DATABASE auth TO auth_recovery_operator;
GRANT USAGE ON SCHEMA auth TO auth_recovery_operator;
GRANT SELECT ON auth.roles, auth.user_roles TO auth_recovery_operator;
GRANT SELECT ON auth.users, auth.sessions TO auth_recovery_operator;
GRANT UPDATE(auth_version) ON auth.users TO auth_recovery_operator;
GRANT SELECT(user_id), UPDATE(password_hash) ON auth.password_credentials TO auth_recovery_operator;
GRANT UPDATE(revoked_at) ON auth.sessions TO auth_recovery_operator;
GRANT SELECT, DELETE ON auth.password_resets, auth.password_reset_outbox,
  auth.mfa_enrollments, auth.mfa_login_challenges,
  auth.email_login_challenges, auth.email_login_outbox,
  auth.email_bindings TO auth_recovery_operator;
GRANT INSERT ON auth.password_audit TO auth_recovery_operator;
GRANT USAGE ON SEQUENCE auth.password_audit_id_seq TO auth_recovery_operator;
