-- Template identifiers: adapt auth/auth_owner/auth_runtime before another project.
-- Create auth_runtime LOGIN with an operator-provisioned password first.
-- Run as auth_owner in database auth, after migrations and after every restore.
GRANT CONNECT ON DATABASE auth TO auth_runtime;
GRANT USAGE ON SCHEMA auth TO auth_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO auth_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth TO auth_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth
  GRANT USAGE, SELECT ON SEQUENCES TO auth_runtime;
