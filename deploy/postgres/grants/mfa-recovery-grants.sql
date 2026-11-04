-- Apply as migration owner; adapt database auth. Never grant to runtime/password operator.
-- DBA creates auth_mfa_recovery_operator NOLOGIN and a separate operator LOGIN first.
GRANT CONNECT ON DATABASE auth TO auth_mfa_recovery_operator;
GRANT USAGE ON SCHEMA auth TO auth_mfa_recovery_operator;
GRANT SELECT(id,status,deleted_at,auth_version) ON auth.users TO auth_mfa_recovery_operator;
GRANT SELECT(user_id,request_id,auth_version,state,expires_at) ON auth.mfa_recovery_requests TO auth_mfa_recovery_operator;
GRANT EXECUTE ON FUNCTION auth.decide_mfa_recovery(UUID,UUID,BIGINT,BOOLEAN,TEXT,TEXT) TO auth_mfa_recovery_operator;
