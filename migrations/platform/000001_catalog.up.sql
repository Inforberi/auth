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
