-- Dedicated credential reader in the catalog; create this NOINHERIT LOGIN separately.
-- Never grant this identity to the HTTP API role or use provisioning/root credentials.
GRANT CONNECT ON DATABASE auth_platform TO auth_platform_runtime_reader;
GRANT USAGE ON SCHEMA platform TO auth_platform_runtime_reader;
GRANT SELECT ON platform.operator_realm,platform.projects,platform.project_preparations,platform.project_secrets
  TO auth_platform_runtime_reader;
