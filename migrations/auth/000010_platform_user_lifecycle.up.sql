CREATE TABLE auth.platform_user_lifecycle (
  operation_id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  actor_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES auth.users(id),
  action text NOT NULL CHECK (action IN ('active','blocked','delete','temporary_password','initial_email')),
  email_id uuid,
  expected_version bigint NOT NULL CHECK(expected_version > 0),
  auth_version bigint NOT NULL CHECK(auth_version BETWEEN expected_version AND expected_version + 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON auth.platform_user_lifecycle FROM PUBLIC;

CREATE TABLE auth.platform_user_creations (
  operation_id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  actor_id uuid NOT NULL,
  fingerprint text NOT NULL CHECK(fingerprint = '' OR length(fingerprint) = 64),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON auth.platform_user_creations FROM PUBLIC;

ALTER TABLE auth.account_provisions
  DROP CONSTRAINT account_provisions_pkey,
  ALTER COLUMN actor_id DROP NOT NULL,
  ADD COLUMN platform_operation_id uuid UNIQUE REFERENCES auth.platform_user_creations(operation_id),
  ADD CONSTRAINT account_provisions_actor_request UNIQUE (actor_id, request_key),
  ADD CONSTRAINT account_provisions_actor_scope CHECK (
    (actor_id IS NULL AND platform_operation_id IS NOT NULL AND platform_operation_id = request_key)
    OR (actor_id IS NOT NULL AND platform_operation_id IS NULL)
  );

CREATE TABLE auth.platform_management_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('role_updated','administrator_granted','administrator_revoked','mfa_updated','retention_updated','smtp_updated','provider_updated','telegram_bot_updated','telegram_webhook_registered')),
  target text NOT NULL,
  previous_value jsonb NOT NULL,
  next_value jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON auth.platform_management_audit FROM PUBLIC;

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
    WHERE s.singleton AND s.mode = 'api' AND
      (s.initialized OR (to_regclass('auth.project_identity') IS NOT NULL AND p.policy IS NOT NULL));
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
