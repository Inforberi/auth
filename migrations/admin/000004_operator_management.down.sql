DROP TABLE platform.operator_management;
CREATE OR REPLACE FUNCTION auth.has_administrative_access(owner_id UUID) RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
  SELECT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
    WHERE ur.user_id=owner_id AND ((r.system AND r.key='super_admin') OR EXISTS(
      SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id AND rp.permission_key IN (
        'access.roles.manage','access.assignments.manage','accounts.email.bind','accounts.users.manage',
        'accounts.users.read','accounts.users.status.manage','accounts.users.delete','auth.settings.manage'))));
$$;
CREATE OR REPLACE FUNCTION auth.administrative_mfa_required(owner_id UUID) RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
  SELECT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
    WHERE ur.user_id=owner_id AND ((r.system AND r.key='super_admin') OR EXISTS(
      SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id AND rp.permission_key IN (
        'access.roles.manage','access.assignments.manage','accounts.email.bind','accounts.users.manage',
        'accounts.users.status.manage','accounts.users.delete','auth.settings.manage'))));
$$;
