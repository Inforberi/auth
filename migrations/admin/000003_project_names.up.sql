CREATE TABLE platform.project_name_changes (
  project_id uuid NOT NULL REFERENCES platform.projects(id),
  operation_id uuid NOT NULL CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  actor_id uuid NOT NULL,
  previous_name text NOT NULL CHECK (octet_length(previous_name) BETWEEN 1 AND 200),
  name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 200 AND name=btrim(name)),
  reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 500 AND reason=btrim(reason)),
  expected_version bigint NOT NULL CHECK (expected_version > 0),
  version bigint NOT NULL CHECK (version IN (expected_version, expected_version + 1)),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(project_id, operation_id)
);
