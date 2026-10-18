-- Template: create auth_platform_runtime LOGIN separately, then run as migration owner
-- inside the platform database after Auth and platform migrations. No CREATE DATABASE role.
GRANT CONNECT ON DATABASE auth_platform TO auth_platform_runtime;
GRANT USAGE ON SCHEMA auth,platform TO auth_platform_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_platform_runtime;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON auth.restore_audit FROM auth_platform_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA auth TO auth_platform_runtime;

GRANT SELECT ON platform.operator_realm TO auth_platform_runtime;
GRANT UPDATE(initialized_at,first_operator_id) ON platform.operator_realm TO auth_platform_runtime;
GRANT SELECT,INSERT ON platform.operator_permissions,platform.operator_audit TO auth_platform_runtime;
GRANT SELECT ON platform.projects TO auth_platform_runtime;

-- Deliberately no blanket platform DML/default privileges, schema CREATE or recovery decision grants.
