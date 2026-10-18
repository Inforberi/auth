CREATE SCHEMA platform;
REVOKE ALL ON SCHEMA platform FROM PUBLIC;

CREATE TABLE platform.projects (
  id UUID PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
  slug TEXT NOT NULL UNIQUE CHECK (
    octet_length(slug) BETWEEN 1 AND 63 AND slug ~ '^[a-z]([a-z0-9-]*[a-z0-9])?$'
    AND slug NOT IN ('admin','api','auth','console','platform','www')
  ),
  name TEXT NOT NULL CHECK (
    octet_length(name) BETWEEN 1 AND 200 AND name = btrim(name)
    AND name !~ '[[:cntrl:]]'
  ),
  origin TEXT NOT NULL UNIQUE CHECK (
    octet_length(origin) BETWEEN 9 AND 280
    AND origin ~ '^https://[a-z0-9.-]+(:[0-9]{1,5})?$'
  ),
  desired_state TEXT NOT NULL DEFAULT 'enabled' CHECK (desired_state IN ('enabled','suspended')),
  phase TEXT NOT NULL DEFAULT 'pending' CHECK (phase IN ('pending','provisioning','failed','ready')),
  version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
  generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
  storage_target TEXT NOT NULL CHECK (storage_target ~ '^[a-z][a-z0-9_-]{0,63}$'),
  database_name TEXT CHECK (database_name ~ '^[a-z][a-z0-9_]{0,62}$'),
  credential_ref TEXT CHECK (credential_ref ~ '^[a-zA-Z0-9][a-zA-Z0-9:_.-]{0,159}$'),
  schema_version BIGINT NOT NULL DEFAULT 0 CHECK (schema_version >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now() CHECK (updated_at >= created_at),
  CHECK (phase <> 'ready' OR (database_name IS NOT NULL AND credential_ref IS NOT NULL AND schema_version > 0))
);

CREATE INDEX projects_page ON platform.projects(created_at DESC,id DESC);
CREATE INDEX projects_phase_page ON platform.projects(phase,created_at DESC,id DESC);
REVOKE ALL ON platform.projects FROM PUBLIC;

CREATE TABLE platform.project_events (
  project_id UUID NOT NULL REFERENCES platform.projects(id),
  operation_id UUID NOT NULL CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  action TEXT NOT NULL CHECK (action IN ('begin_preparation','fail_preparation','finish_preparation','retry','suspend','resume')),
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('operator','provisioner')),
  actor_id UUID NOT NULL CHECK (actor_id <> '00000000-0000-0000-0000-000000000000'::uuid),
  reason TEXT NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 500 AND reason=btrim(reason) AND reason !~ '[[:cntrl:]]'),
  from_state TEXT NOT NULL CHECK (from_state IN ('enabled','suspended')),
  from_phase TEXT NOT NULL CHECK (from_phase IN ('pending','provisioning','failed','ready')),
  from_version BIGINT NOT NULL CHECK (from_version > 0),
  from_generation BIGINT NOT NULL CHECK (from_generation > 0),
  to_state TEXT NOT NULL CHECK (to_state IN ('enabled','suspended')),
  to_phase TEXT NOT NULL CHECK (to_phase IN ('pending','provisioning','failed','ready')),
  to_version BIGINT NOT NULL CHECK (to_version=from_version+1),
  to_generation BIGINT NOT NULL CHECK (to_generation=from_generation+1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(project_id,operation_id)
);
CREATE INDEX project_events_page ON platform.project_events(project_id,created_at DESC,operation_id DESC);
REVOKE ALL ON platform.project_events FROM PUBLIC;
