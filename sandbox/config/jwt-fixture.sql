-- Только существующий synthetic Ivan в auth-sandbox, не bootstrap production access.
BEGIN;
SET LOCAL lock_timeout = '3s';
SELECT pg_advisory_xact_lock(734013981);
WITH created AS (
  INSERT INTO auth.roles(key,name) VALUES ('sandbox_reader','Sandbox reader') ON CONFLICT(key) DO NOTHING RETURNING id
)
INSERT INTO auth.role_permissions(role_id,permission_key)
SELECT id,'sandbox.records.read' FROM created;
WITH assigned AS (
  INSERT INTO auth.user_roles(user_id,role_id)
  SELECT u.id,r.id FROM auth.users u JOIN auth.user_emails e ON e.user_id=u.id CROSS JOIN auth.roles r
  WHERE e.email='ivan@sandbox.example' AND u.status='active' AND u.deleted_at IS NULL AND r.key='sandbox_reader'
  ON CONFLICT DO NOTHING RETURNING user_id
)
UPDATE auth.users SET auth_version=auth_version+1,access_version=access_version+1
WHERE id IN (SELECT user_id FROM assigned);
COMMIT;
