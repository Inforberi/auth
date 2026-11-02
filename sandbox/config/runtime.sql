-- Synthetic local sandbox only; never apply to a shared/production database.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='auth_runtime') THEN
    CREATE ROLE auth_runtime LOGIN PASSWORD 'sandbox-runtime-only';
  END IF;
END;
$$;
