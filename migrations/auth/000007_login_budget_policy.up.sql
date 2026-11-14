CREATE TABLE auth.login_budget_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    version bigint NOT NULL DEFAULT 1 CHECK(version > 0),
    policy jsonb CHECK(jsonb_typeof(policy) = 'object')
);
INSERT INTO auth.login_budget_policy DEFAULT VALUES;

CREATE TABLE auth.login_budget_policy_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    actor_id uuid NOT NULL,
    version bigint NOT NULL CHECK(version > 1),
    previous_policy jsonb NOT NULL,
    next_policy jsonb NOT NULL
);
CREATE INDEX login_budget_policy_audit_retention ON auth.login_budget_policy_audit(created_at,id);
