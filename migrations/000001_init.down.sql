DROP INDEX IF EXISTS idx_sessions_user_id;

DROP TABLE IF EXISTS auth.sessions;

DROP TABLE IF EXISTS auth.password_credentials;

DROP TABLE IF EXISTS auth.user_profile;

DROP TABLE IF EXISTS auth.users;

DROP SCHEMA IF EXISTS auth;