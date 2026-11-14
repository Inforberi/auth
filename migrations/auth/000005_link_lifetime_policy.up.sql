CREATE TABLE auth.link_lifetime_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    version bigint NOT NULL DEFAULT 1 CHECK(version > 0),
    policy jsonb CHECK(jsonb_typeof(policy) = 'object')
);
INSERT INTO auth.link_lifetime_policy DEFAULT VALUES;

CREATE TABLE auth.link_lifetime_policy_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    actor_id uuid NOT NULL,
    version bigint NOT NULL CHECK(version > 1),
    previous_policy jsonb NOT NULL,
    next_policy jsonb NOT NULL
);
CREATE INDEX link_lifetime_policy_audit_retention ON auth.link_lifetime_policy_audit(created_at,id);
