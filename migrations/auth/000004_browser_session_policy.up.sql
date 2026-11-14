CREATE TABLE auth.browser_session_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    version bigint NOT NULL DEFAULT 1 CHECK(version > 0),
    policy jsonb CHECK(jsonb_typeof(policy) = 'object')
);
INSERT INTO auth.browser_session_policy DEFAULT VALUES;

CREATE TABLE auth.browser_session_policy_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    actor_id uuid NOT NULL,
    version bigint NOT NULL CHECK(version > 1),
    previous_policy jsonb NOT NULL,
    next_policy jsonb NOT NULL
);
CREATE INDEX browser_session_policy_audit_retention ON auth.browser_session_policy_audit(created_at,id);

ALTER TABLE auth.sessions
    ADD COLUMN browser_idle_seconds bigint,
    ADD COLUMN browser_refresh_seconds bigint,
    ADD CONSTRAINT browser_session_refresh_policy CHECK (
        (browser_idle_seconds IS NULL AND browser_refresh_seconds IS NULL) OR
        (credential_profile = 'browser' AND browser_idle_seconds IS NOT NULL AND
         browser_refresh_seconds IS NOT NULL AND browser_refresh_seconds > 0 AND
         browser_refresh_seconds < browser_idle_seconds)
    );

CREATE FUNCTION auth.bind_browser_session_policy() RETURNS trigger
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

-- PostgreSQL runs same-event triggers by name. Role binding applies the admin deadlines second.
CREATE TRIGGER sessions_browser_policy BEFORE INSERT ON auth.sessions
    FOR EACH ROW EXECUTE FUNCTION auth.bind_browser_session_policy();
