-- Template identifiers: adapt auth/auth_owner/auth_runtime before another project.
-- Create auth_runtime LOGIN with an operator-provisioned password first.
-- Run as auth_owner in database auth, after migrations and after every restore.
GRANT CONNECT ON DATABASE auth TO auth_runtime;
GRANT USAGE ON SCHEMA auth TO auth_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO auth_runtime;
-- Only an offline database-owner restore may write this operational audit.
REVOKE INSERT, UPDATE, DELETE ON auth.restore_audit FROM auth_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON auth.platform_role_creations FROM auth_runtime;
REVOKE INSERT ON auth.platform_role_creations FROM auth_runtime;
GRANT INSERT(operation_id,realm_id,actor_id,project_id,binding,request,role_id,role_snapshot)
  ON auth.platform_role_creations TO auth_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth TO auth_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth
  GRANT USAGE, SELECT ON SEQUENCES TO auth_runtime;
