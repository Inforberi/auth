-- Apply only to a new platform Auth realm, never to an existing project database.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM auth.users)
    OR EXISTS (SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL OR operator_hash IS NOT NULL)
    OR EXISTS (SELECT 1 FROM auth.roles WHERE key='super_admin' AND system) THEN
    RAISE EXCEPTION 'platform operator realm requires unused Auth setup';
  END IF;
END $$;

CREATE TABLE platform.operator_realm (
  singleton BOOLEAN PRIMARY KEY CHECK (singleton),
  id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid()
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
  initialized_at TIMESTAMPTZ,
  first_operator_id UUID REFERENCES auth.users(id),
  CHECK ((initialized_at IS NULL) = (first_operator_id IS NULL))
);
INSERT INTO platform.operator_realm(singleton) VALUES(true);

-- Separate authority: project role_permissions (including similarly named keys) do not grant these rights.
CREATE TABLE platform.operator_permissions (
  user_id UUID NOT NULL REFERENCES auth.users(id),
  permission_key TEXT NOT NULL CHECK (permission_key IN (
    'platform.projects.read','platform.projects.manage','platform.project_users.manage',
    'platform.project_access.manage','platform.project_settings.manage','platform.operators.manage'
  )),
  PRIMARY KEY(user_id,permission_key)
);

CREATE TABLE platform.operator_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID NOT NULL REFERENCES auth.users(id),
  event TEXT NOT NULL CHECK (event='owner_initialized'),
  permissions TEXT[] NOT NULL CHECK (cardinality(permissions)=6),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON platform.operator_realm,platform.operator_permissions,platform.operator_audit FROM PUBLIC;
