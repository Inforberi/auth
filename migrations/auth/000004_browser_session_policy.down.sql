DROP TRIGGER sessions_browser_policy ON auth.sessions;
DROP FUNCTION auth.bind_browser_session_policy();
ALTER TABLE auth.sessions DROP COLUMN browser_idle_seconds, DROP COLUMN browser_refresh_seconds;
DROP TABLE auth.browser_session_policy_audit;
DROP TABLE auth.browser_session_policy;
