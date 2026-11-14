CREATE TABLE auth.settings_source (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    mode text NOT NULL CHECK(mode IN ('api','env')),
    initialized boolean NOT NULL DEFAULT false,
    generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
    fingerprint bytea,
    key_binding bytea,
    component_hashes jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(component_hashes)='object'),
    CHECK((mode='api' AND fingerprint IS NULL AND key_binding IS NULL) OR (mode='env' AND fingerprint IS NOT NULL AND key_binding IS NOT NULL AND octet_length(fingerprint)=32 AND octet_length(key_binding)=32))
);
INSERT INTO auth.settings_source(singleton,mode) VALUES(true,'api');
CREATE TABLE auth.settings_source_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    generation bigint NOT NULL,
    mode text NOT NULL CHECK(mode IN ('api','env')),
    event text NOT NULL CHECK(event IN ('initialize','synchronize'))
);
CREATE INDEX settings_source_audit_retention ON auth.settings_source_audit(created_at,id);
