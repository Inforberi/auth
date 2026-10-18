-- Apply as migration owner only to the platform DB; adapt auth_platform.
-- First create auth_recovery_operator, auth_mfa_recovery_operator,
-- platform_password_recovery_operator and platform_mfa_recovery_operator NOLOGIN.
-- Apply deploy/recovery-grants.sql and deploy/mfa-recovery-grants.sql with
-- database auth -> auth_platform, and role auth_recovery_operator ->
-- platform_password_recovery_operator / auth_mfa_recovery_operator ->
-- platform_mfa_recovery_operator respectively; then apply this file.
-- Use two separate personal LOGIN identities, one group each; never runtime.
-- MEMBER is required by the existing Auth guards, but must not inherit data
-- privileges from legacy/project DBs or permit SET ROLE into their groups.
GRANT auth_recovery_operator TO platform_password_recovery_operator WITH INHERIT FALSE, SET FALSE;
GRANT auth_mfa_recovery_operator TO platform_mfa_recovery_operator WITH INHERIT FALSE, SET FALSE;
GRANT USAGE ON SCHEMA platform TO platform_password_recovery_operator, platform_mfa_recovery_operator;
GRANT SELECT ON platform.operator_realm, platform.operator_permissions
  TO platform_password_recovery_operator, platform_mfa_recovery_operator;
