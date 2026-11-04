-- Однократная установка в ОТДЕЛЬНОЙ maintenance-БД PostgreSQL 18, не в Auth/каталоге.
-- LOGIN auth_storage_executor создаёт оператор: CREATEDB CREATEROLE NOINHERIT,
-- без SUPERUSER/REPLICATION/BYPASSRLS. Пароль/TLS задаются вне этого файла.
-- psql -v ON_ERROR_STOP=1 -v realm=<platform UUID> -v target=primary -f ...
BEGIN;
CREATE SCHEMA provisioning;
REVOKE ALL ON SCHEMA provisioning FROM PUBLIC;
CREATE TABLE provisioning.target (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    realm_id UUID NOT NULL CHECK (realm_id <> '00000000-0000-0000-0000-000000000000'),
    target TEXT NOT NULL CHECK (target ~ '^[a-z][a-z0-9_-]{0,63}$')
);
INSERT INTO provisioning.target(realm_id,target) VALUES (:'realm', :'target');
CREATE TABLE provisioning.resources (
    project_id UUID PRIMARY KEY CHECK (project_id <> '00000000-0000-0000-0000-000000000000'),
    reservation_id UUID NOT NULL UNIQUE CHECK (reservation_id <> '00000000-0000-0000-0000-000000000000'),
    owner_oid OID NOT NULL UNIQUE,
    database_oid OID UNIQUE,
    generation BIGINT NOT NULL CHECK (generation > 0),
    schema_started BOOLEAN NOT NULL DEFAULT FALSE,
    runtime_oid OID UNIQUE,
    password_fingerprint BYTEA,
    onboarding_state TEXT NOT NULL DEFAULT 'closed' CHECK (onboarding_state IN ('closed','opening','open','closing')),
    onboarding_operation_id UUID,
    onboarding_version BIGINT,
    onboarding_generation BIGINT,
    CHECK ((onboarding_operation_id IS NULL AND onboarding_version IS NULL AND onboarding_generation IS NULL AND onboarding_state='closed')
        OR (onboarding_operation_id IS NOT NULL AND onboarding_operation_id <> '00000000-0000-0000-0000-000000000000'
            AND onboarding_version IS NOT NULL AND onboarding_version>0 AND onboarding_generation IS NOT NULL
            AND onboarding_generation>0 AND runtime_oid IS NOT NULL AND schema_started)),
    CHECK ((runtime_oid IS NULL AND password_fingerprint IS NULL)
        OR (runtime_oid IS NOT NULL AND runtime_oid <> 0 AND octet_length(password_fingerprint)=32 AND password_fingerprint IS NOT NULL)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA provisioning FROM PUBLIC;
GRANT USAGE ON SCHEMA provisioning TO auth_storage_executor;
GRANT SELECT ON provisioning.target, provisioning.resources TO auth_storage_executor;
GRANT INSERT(project_id,reservation_id,owner_oid,generation), UPDATE(database_oid,generation)
    ON provisioning.resources TO auth_storage_executor;
GRANT UPDATE(schema_started) ON provisioning.resources TO auth_storage_executor;
GRANT UPDATE(runtime_oid,password_fingerprint) ON provisioning.resources TO auth_storage_executor;
GRANT UPDATE(onboarding_state,onboarding_operation_id,onboarding_version,onboarding_generation)
    ON provisioning.resources TO auth_storage_executor;
DO $$ BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO auth_storage_executor', current_database());
END $$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
COMMIT;
