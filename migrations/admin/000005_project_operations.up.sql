CREATE TABLE platform.project_preparation_requests (
    operation_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES platform.projects(id),
    actor_id uuid NOT NULL REFERENCES auth.users(id),
    expected_version bigint NOT NULL CHECK(expected_version > 0),
    expected_generation bigint NOT NULL CHECK(expected_generation > 0),
    stage text NOT NULL DEFAULT 'requested'
        CHECK(stage IN ('requested','running','failed','managed_configuration_prepared','ready')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    retry_after timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX project_preparation_requests_project ON platform.project_preparation_requests(project_id,created_at DESC);
CREATE UNIQUE INDEX project_preparation_requests_epoch ON platform.project_preparation_requests(project_id,expected_generation);
CREATE INDEX project_preparation_requests_queue ON platform.project_preparation_requests(retry_after,operation_id)
    WHERE stage IN ('requested','running','failed','managed_configuration_prepared') AND attempts < 5;

REVOKE ALL ON platform.project_preparation_requests FROM PUBLIC;

CREATE TABLE platform.project_deletions (
    operation_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES platform.projects(id),
    actor_id uuid NOT NULL REFERENCES auth.users(id),
    version bigint NOT NULL,
    generation bigint NOT NULL,
    acknowledge_users boolean NOT NULL,
    stage text NOT NULL DEFAULT 'confirmed' CHECK(stage IN ('confirmed','draining','verified','deleted','expired','users_present')),
    retry_after timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '15 minutes'
);
CREATE UNIQUE INDEX project_deletions_active ON platform.project_deletions(project_id)
    WHERE stage IN ('confirmed','draining','verified','deleted');
CREATE INDEX project_deletions_queue ON platform.project_deletions(retry_after,operation_id)
    WHERE stage IN ('confirmed','draining','verified');
REVOKE ALL ON platform.project_deletions FROM PUBLIC;
