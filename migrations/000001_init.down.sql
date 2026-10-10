DROP TABLE IF EXISTS auth.invitation_audit;
DROP TABLE IF EXISTS auth.invitation_outbox;
DROP TABLE IF EXISTS auth.account_invitations;
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

DROP TABLE IF EXISTS auth.email_verification_audit;
DROP TABLE IF EXISTS auth.email_verification_outbox;
DROP TABLE IF EXISTS auth.email_verifications;

DROP TABLE IF EXISTS auth.password_credentials;

DROP TABLE IF EXISTS auth.user_profile;

DROP TABLE IF EXISTS auth.user_emails;
DROP TABLE IF EXISTS auth.users;

DROP FUNCTION IF EXISTS auth.set_updated_at();
DROP SCHEMA IF EXISTS auth;
