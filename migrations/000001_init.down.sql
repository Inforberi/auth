DROP TABLE IF EXISTS auth.initial_setup;
DROP TABLE IF EXISTS auth.email_login_audit;
DROP TABLE IF EXISTS auth.email_bindings;
DROP TABLE IF EXISTS auth.email_login_outbox;
DROP TABLE IF EXISTS auth.email_login_challenges;
DROP TABLE IF EXISTS auth.temporary_password_reissues;
DROP TABLE IF EXISTS auth.temporary_password_tokens;
DROP TABLE IF EXISTS auth.temporary_password_credentials;
DROP TABLE IF EXISTS auth.invitation_audit;
DROP TABLE IF EXISTS auth.invitation_outbox;
DROP TABLE IF EXISTS auth.account_invitations;
DROP TABLE IF EXISTS auth.invitation_reissues;
DROP TABLE IF EXISTS auth.account_provisions;
DROP TABLE IF EXISTS auth.email_change_audit;
DROP TABLE IF EXISTS auth.email_change_outbox;
DROP TABLE IF EXISTS auth.email_changes;
DROP TABLE IF EXISTS auth.account_status_audit;
DROP TABLE IF EXISTS auth.account_deletion_audit;
DROP TABLE IF EXISTS auth.password_audit;
DROP TABLE IF EXISTS auth.password_reset_outbox;
DROP TABLE IF EXISTS auth.password_resets;
DROP TABLE IF EXISTS auth.sessions;
DROP TABLE IF EXISTS auth.mfa_audit;
DROP TABLE IF EXISTS auth.mfa_recovery_codes;
DROP TABLE IF EXISTS auth.mfa_enrollments;
DROP TABLE IF EXISTS auth.mfa_login_challenges;
DROP TABLE IF EXISTS auth.mfa_totp;

DROP TABLE IF EXISTS auth.email_verification_audit;
DROP TABLE IF EXISTS auth.email_verification_outbox;
DROP TABLE IF EXISTS auth.email_verifications;

DROP TABLE IF EXISTS auth.password_credentials;

DROP TABLE IF EXISTS auth.user_profile;

DROP TABLE IF EXISTS auth.user_emails;
DROP TABLE IF EXISTS auth.identity_audit;
DROP TABLE IF EXISTS auth.linked_identities;
DROP TABLE IF EXISTS auth.access_audit;
DROP TABLE IF EXISTS auth.user_roles;
DROP TABLE IF EXISTS auth.role_permissions;
DROP TABLE IF EXISTS auth.roles;
DROP TABLE IF EXISTS auth.users;

DROP FUNCTION IF EXISTS auth.set_updated_at();
DROP SCHEMA IF EXISTS auth;
