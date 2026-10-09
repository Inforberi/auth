DROP TABLE IF EXISTS auth.email_verification_audit;
DROP TABLE IF EXISTS auth.email_verification_outbox;
DROP TABLE IF EXISTS auth.email_verifications;

DROP TABLE IF EXISTS auth.password_credentials;

DROP TABLE IF EXISTS auth.user_profile;

DROP TABLE IF EXISTS auth.user_emails;
DROP TABLE IF EXISTS auth.users;

DROP FUNCTION IF EXISTS auth.set_updated_at();
DROP SCHEMA IF EXISTS auth;
