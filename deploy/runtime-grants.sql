-- Template identifiers: adapt auth/auth_owner/auth_runtime before another project.
-- Create auth_runtime LOGIN with an operator-provisioned password first.
-- Run as auth_owner in database auth, after migrations and after every restore.
GRANT CONNECT ON DATABASE auth TO auth_runtime;
GRANT USAGE ON SCHEMA auth TO auth_runtime;
-- Keep broad grants and protected-object revokes atomic, including psql autocommit.
DO $$
BEGIN
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO auth_runtime;
-- Only an offline database-owner restore may write this operational audit.
REVOKE INSERT, UPDATE, DELETE ON auth.restore_audit FROM auth_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON auth.platform_role_creations FROM auth_runtime;
REVOKE INSERT ON auth.platform_role_creations FROM auth_runtime;
GRANT INSERT(operation_id,realm_id,actor_id,project_id,binding,request,role_id,role_snapshot,admission_id)
  ON auth.platform_role_creations TO auth_runtime;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON auth.platform_role_assignments FROM auth_runtime;
GRANT INSERT(operation_id,realm_id,actor_id,project_id,binding,request,user_id,role_id,role_snapshot,access_version,changed,admission_id)
  ON auth.platform_role_assignments TO auth_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth TO auth_runtime;
-- Project-only projection may not exist in a standalone database.
  IF to_regclass('auth.project_identity') IS NOT NULL THEN
    IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
      WHERE ns.nspname='auth' AND c.relname='project_identity' AND c.relkind='v' AND c.relowner=ns.nspowner) THEN
      RAISE EXCEPTION 'unexpected project identity relation';
    END IF;
    REVOKE ALL ON auth.project_identity FROM auth_runtime;
    GRANT SELECT ON auth.project_identity TO auth_runtime;
  END IF;
END;
$$;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth
  GRANT USAGE, SELECT ON SEQUENCES TO auth_runtime;
