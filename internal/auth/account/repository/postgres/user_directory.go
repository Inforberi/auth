package postgres

const directoryActor = `WITH directory_actor AS MATERIALIZED (
	SELECT EXISTS (
		SELECT 1 FROM auth.sessions s JOIN auth.users actor ON actor.id=s.user_id AND actor.auth_version=s.auth_version
		WHERE actor.id=$1 AND s.token_hash=$2 AND actor.status='active' AND actor.deleted_at IS NULL
		AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()
		AND EXISTS (SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
			WHERE ur.user_id=actor.id AND rp.permission_key=$3)
	) AS allowed
) `

// Prefer the password contact; passwordless owners use the first retained contact by UUID.
const directoryEmail = ` LEFT JOIN LATERAL (
	SELECT e.email,e.verified_at FROM auth.user_emails e WHERE e.user_id=u.id
	AND e.id=COALESCE((SELECT email_id FROM auth.password_credentials WHERE user_id=u.id),
		(SELECT id FROM auth.user_emails WHERE user_id=u.id ORDER BY id LIMIT 1))
) email ON true `
