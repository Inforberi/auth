DROP TABLE auth.platform_management_audit;
-- Rollback requires resolving platform-issued provisions before restoring the local-only schema.
ALTER TABLE auth.account_provisions
  ALTER COLUMN actor_id SET NOT NULL,
  DROP CONSTRAINT account_provisions_actor_scope,
  DROP COLUMN platform_operation_id,
  DROP CONSTRAINT account_provisions_actor_request,
  ADD PRIMARY KEY (actor_id,request_key);
DROP TABLE auth.platform_user_creations;
DROP TABLE auth.platform_user_lifecycle;

DO $migration$
BEGIN
  IF to_regprocedure('auth.bind_browser_session_policy()') IS NOT NULL THEN
    CREATE OR REPLACE FUNCTION auth.bind_browser_session_policy() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE lifetime jsonb;
BEGIN
    IF NEW.credential_profile <> 'browser' THEN
        RETURN NEW;
    END IF;

    SELECT p.policy INTO lifetime
    FROM auth.settings_source s LEFT JOIN auth.browser_session_policy p ON p.singleton
    WHERE s.singleton AND s.initialized AND s.mode = 'api';
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    IF lifetime IS NULL THEN
        RAISE EXCEPTION 'browser session policy is not initialized';
    END IF;

    NEW.browser_idle_seconds := (lifetime->>'idleSeconds')::bigint;
    NEW.browser_refresh_seconds := (lifetime->>'refreshThresholdSeconds')::bigint;
    NEW.admin_absolute_seconds := (lifetime->>'adminAbsoluteSeconds')::bigint;
    NEW.idle_timeout_seconds := (lifetime->>'adminIdleSeconds')::bigint;
    NEW.activity_interval_seconds := (lifetime->>'adminActivitySeconds')::bigint;
    NEW.absolute_expires_at := NEW.created_at + (lifetime->>'absoluteSeconds')::bigint * interval '1 second';
    NEW.expires_at := NEW.created_at + NEW.browser_idle_seconds * interval '1 second';
    RETURN NEW;
END;
$$;
  END IF;
END;
$migration$;
