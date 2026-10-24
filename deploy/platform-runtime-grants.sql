-- Template: create auth_platform_runtime LOGIN separately, then run as migration owner
-- inside the platform database after Auth and platform migrations. No CREATE DATABASE role.
GRANT CONNECT ON DATABASE auth_platform TO auth_platform_runtime;
GRANT USAGE ON SCHEMA auth,platform TO auth_platform_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_platform_runtime;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON auth.restore_audit FROM auth_platform_runtime;
REVOKE ALL ON auth.platform_role_creations FROM auth_platform_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA auth TO auth_platform_runtime;

GRANT SELECT ON platform.operator_realm TO auth_platform_runtime;
GRANT UPDATE(initialized_at,first_operator_id) ON platform.operator_realm TO auth_platform_runtime;
GRANT SELECT,INSERT ON platform.operator_permissions,platform.operator_audit TO auth_platform_runtime;
GRANT SELECT ON platform.projects TO auth_platform_runtime;
GRANT SELECT(project_id,reservation_id,storage_target,operation_id,version,generation,secrets_created,onboarding_admitted)
  ON platform.project_preparations TO auth_platform_runtime;
GRANT SELECT(project_id,reservation_id,storage_target,database_oid,owner_oid,runtime_oid,schema_version)
  ON platform.project_secrets TO auth_platform_runtime;
GRANT INSERT(id,slug,name,origin,storage_target) ON platform.projects TO auth_platform_runtime;
GRANT SELECT,INSERT ON platform.project_creations TO auth_platform_runtime;
GRANT SELECT ON platform.project_role_intents TO auth_platform_runtime;
GRANT SELECT ON platform.project_role_admissions,platform.project_role_outcomes TO auth_platform_runtime;
GRANT INSERT(operation_id,created_at,expires_at) ON platform.project_role_admissions TO auth_platform_runtime;
GRANT INSERT(operation_id,admission_id,role_snapshot) ON platform.project_role_outcomes TO auth_platform_runtime;
GRANT INSERT(operation_id,project_id,realm_id,actor_id,version,generation,binding,request)
  ON platform.project_role_intents TO auth_platform_runtime;
-- Row-locking SELECT requires UPDATE on at least one column of operator_permissions.
GRANT UPDATE(permission_key) ON platform.operator_permissions TO auth_platform_runtime;
GRANT UPDATE(desired_state,phase,version,generation,updated_at) ON platform.projects TO auth_platform_runtime;
GRANT SELECT ON platform.project_events TO auth_platform_runtime;
GRANT INSERT(project_id,operation_id,action,actor_kind,actor_id,reason,
  from_state,from_phase,from_version,from_generation,to_state,to_phase,to_version,to_generation)
  ON platform.project_events TO auth_platform_runtime;

-- Deliberately no blanket platform DML/default privileges, schema CREATE or recovery decision grants.
