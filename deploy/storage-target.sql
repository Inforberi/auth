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
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA provisioning FROM PUBLIC;
GRANT USAGE ON SCHEMA provisioning TO auth_storage_executor;
GRANT SELECT ON provisioning.target, provisioning.resources TO auth_storage_executor;
GRANT INSERT(project_id,reservation_id,owner_oid,generation), UPDATE(database_oid,generation)
    ON provisioning.resources TO auth_storage_executor;
GRANT UPDATE(schema_started) ON provisioning.resources TO auth_storage_executor;
DO $$ BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO auth_storage_executor', current_database());
END $$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
COMMIT;
