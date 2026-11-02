BEGIN;
SET LOCAL statement_timeout='5s';
SET LOCAL lock_timeout='1s';

INSERT INTO auth.users(id,status,created_at)
VALUES (:'owner','blocked',clock_timestamp()-interval '40 days');

WITH fixture(kind,size) AS (VALUES ('expired',450),('young',12),('live',12),('held',12))
INSERT INTO auth.sessions(credential_profile,token_hash,user_id,auth_version,created_at,
  expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
SELECT CASE WHEN kind='held' THEN 'api' ELSE 'browser' END,
  md5(:'owner'||kind||n::text)||md5('fixture:'||:'owner'||kind||n::text),:'owner',1,
  clock_timestamp()-interval '40 days',
  CASE kind WHEN 'expired' THEN clock_timestamp()-interval '31 days'
    WHEN 'held' THEN clock_timestamp()-interval '31 days'
    WHEN 'young' THEN clock_timestamp()-interval '1 day'
    ELSE clock_timestamp()+interval '1 hour' END,
  clock_timestamp()+interval '2 hours','password',clock_timestamp()-interval '40 days',
  'sandbox-cleanup-'||kind,''
FROM fixture CROSS JOIN LATERAL generate_series(1,size) n;

-- Synthetic held-reference guard, not an issued native lifetime/profile.
-- The blocked owner has no credentials, role, factor or contact.
INSERT INTO auth.refresh_families(session_id,audience,scope,idle_seconds,created_at,last_rotated_at,absolute_expires_at)
SELECT id,'sandbox-strict',ARRAY['sandbox.records.read'],3600,
  clock_timestamp()-interval '40 days',clock_timestamp()-interval '40 days',
  clock_timestamp()+interval '1 hour'
FROM auth.sessions WHERE user_id=:'owner' AND user_agent='sandbox-cleanup-held';

INSERT INTO auth.password_audit(user_id,event,created_at)
SELECT :'owner','password_changed',clock_timestamp()-interval '181 days' FROM generate_series(1,450);
INSERT INTO auth.password_audit(user_id,event,created_at)
SELECT :'owner','password_changed',clock_timestamp()-interval '179 days' FROM generate_series(1,12);

-- The test appends an atomic scoped count snapshot, then COMMIT.
