CREATE TABLE platform.operator_management (
  operation_id uuid PRIMARY KEY,
  actor_id uuid NOT NULL REFERENCES auth.users(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  action text NOT NULL CHECK (action IN ('invite','permissions','revoke')),
  permissions text[] NOT NULL CHECK (cardinality(permissions) <= 5),
  fingerprint text NOT NULL CHECK (fingerprint = '' OR length(fingerprint)=64),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON platform.operator_management FROM PUBLIC;
CREATE INDEX operator_management_invited_users ON platform.operator_management(user_id) WHERE action='invite';

CREATE OR REPLACE FUNCTION auth.has_administrative_access(owner_id UUID) RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
  SELECT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
    WHERE ur.user_id=owner_id AND ((r.system AND r.key='super_admin') OR EXISTS(
      SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id AND rp.permission_key IN (
        'access.roles.manage','access.assignments.manage','accounts.email.bind','accounts.users.manage',
        'accounts.users.read','accounts.users.status.manage','accounts.users.delete','auth.settings.manage'))))
  OR EXISTS(SELECT 1 FROM platform.operator_permissions WHERE user_id=owner_id);
$$;

CREATE OR REPLACE FUNCTION auth.administrative_mfa_required(owner_id UUID) RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
  SELECT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
    WHERE ur.user_id=owner_id AND ((r.system AND r.key='super_admin') OR EXISTS(
      SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id AND rp.permission_key IN (
        'access.roles.manage','access.assignments.manage','accounts.email.bind','accounts.users.manage',
        'accounts.users.status.manage','accounts.users.delete','auth.settings.manage'))))
  OR EXISTS(SELECT 1 FROM platform.operator_permissions WHERE user_id=owner_id);
$$;
