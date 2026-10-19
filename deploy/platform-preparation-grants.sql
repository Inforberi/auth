-- Catalog credential only: create this LOGIN separately in the platform database.
-- No Auth access or CREATE DATABASE/ROLE. Storage DDL will use a separate target credential.
GRANT CONNECT ON DATABASE auth_platform TO auth_platform_preparation;
GRANT USAGE ON SCHEMA platform TO auth_platform_preparation;
GRANT SELECT ON platform.operator_realm,platform.projects,platform.project_events,platform.project_preparations TO auth_platform_preparation;
-- Row locking needs one UPDATE column; singleton is constrained to TRUE and cannot change realm identity/state.
GRANT UPDATE(singleton) ON platform.operator_realm TO auth_platform_preparation;
GRANT UPDATE(desired_state,phase,version,generation,updated_at) ON platform.projects TO auth_platform_preparation;
GRANT INSERT(project_id,operation_id,action,actor_kind,actor_id,reason,
  from_state,from_phase,from_version,from_generation,to_state,to_phase,to_version,to_generation)
  ON platform.project_events TO auth_platform_preparation;
GRANT INSERT(project_id,storage_target,operation_id,version,generation) ON platform.project_preparations TO auth_platform_preparation;
GRANT UPDATE(operation_id,version,generation) ON platform.project_preparations TO auth_platform_preparation;
GRANT UPDATE(secrets_created) ON platform.project_preparations TO auth_platform_preparation;
GRANT SELECT ON platform.project_secrets TO auth_platform_preparation;
GRANT INSERT(project_id,reservation_id,storage_target,database_oid,owner_oid,runtime_oid,schema_version,format_version,key_id,ciphertext)
  ON platform.project_secrets TO auth_platform_preparation;
