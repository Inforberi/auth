package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedRestoreProofs(t *testing.T, db *pgxpool.Pool, ctx context.Context, user, mfa, pending string) {
	t.Helper()
	accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) VALUES('https://accounts.google.com','restore-subject',$1)`, user)
	for _, sql := range []string{
		`INSERT INTO auth.password_resets(digest,user_id,auth_version,expires_at) SELECT repeat('a',64),id,auth_version,now()+interval '1 hour' FROM auth.users WHERE id=$1`,
		`INSERT INTO auth.password_reset_outbox(digest,payload,expires_at) SELECT digest,decode(repeat('00',32),'hex'),expires_at FROM auth.password_resets WHERE user_id=$1`,
		`INSERT INTO auth.email_verifications(digest,email_id,expires_at) SELECT repeat('b',64),email_id,now()+interval '1 hour' FROM auth.password_credentials WHERE user_id=$1`,
		`INSERT INTO auth.email_verification_outbox(digest,payload,expires_at) SELECT v.digest,decode(repeat('00',32),'hex'),v.expires_at FROM auth.email_verifications v JOIN auth.password_credentials p ON p.email_id=v.email_id WHERE p.user_id=$1`,
		`INSERT INTO auth.email_login_challenges(digest,user_id,email_id,auth_version,verifier,expires_at) SELECT repeat('c',64),u.id,p.email_id,u.auth_version,repeat('d',64),now()+interval '5 minutes' FROM auth.users u JOIN auth.password_credentials p ON p.user_id=u.id WHERE u.id=$1`,
		`INSERT INTO auth.email_login_outbox(digest,payload,expires_at) SELECT digest,decode(repeat('00',32),'hex'),expires_at FROM auth.email_login_challenges WHERE user_id=$1`,
	} {
		accessExec(t, db, ctx, sql, user)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.email_bindings(user_id,actor_id,actor_session_hash,auth_version,email,verifier,payload,expires_at)
		SELECT id,$2,repeat('e',64),auth_version,'restore-bind@example.test',repeat('f',64),decode(repeat('00',32),'hex'),statement_timestamp()+interval '5 minutes' FROM auth.users WHERE id=$1`, user, mfa)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_enrollments(user_id,digest,auth_version,session_hash,secret,expires_at)
		SELECT id,repeat('1',64),auth_version,repeat('2',64),decode(repeat('00',64),'hex'),statement_timestamp()+interval '5 minutes' FROM auth.users WHERE id=$1`, mfa)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_recovery_requests(user_id,challenge_digest,auth_version,secret,expires_at)
		SELECT user_id,digest,auth_version,decode(repeat('00',64),'hex'),expires_at FROM auth.mfa_login_challenges WHERE user_id=$1`, mfa)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_recovery_outbox(user_id,request_id,payload) SELECT user_id,request_id,decode(repeat('00',32),'hex') FROM auth.mfa_recovery_requests WHERE user_id=$1`, mfa)
	accessExec(t, db, ctx, `INSERT INTO auth.account_invitations(digest,user_id,email_id,auth_version,expires_at)
		SELECT repeat('3',64),u.id,p.invitation_email_id,u.auth_version,now()+interval '1 day' FROM auth.users u JOIN auth.account_provisions p ON p.user_id=u.id WHERE u.id=$1`, pending)
	accessExec(t, db, ctx, `INSERT INTO auth.invitation_outbox(digest,payload,expires_at) SELECT digest,decode(repeat('00',32),'hex'),expires_at FROM auth.account_invitations WHERE user_id=$1`, pending)
}

func restoreStableState(t *testing.T, db *pgxpool.Pool, ctx context.Context) string {
	t.Helper()
	var snapshot string
	err := db.QueryRow(ctx, `SELECT jsonb_build_object(
		'users',(SELECT jsonb_agg(to_jsonb(u)-'auth_version'-'updated_at' ORDER BY id) FROM auth.users u),
		'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM auth.roles r),
		'permissions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY role_id,permission_key) FROM auth.role_permissions p),
		'assignments',(SELECT jsonb_agg(to_jsonb(p) ORDER BY user_id,role_id) FROM auth.user_roles p),
		'emails',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM auth.user_emails e),
		'profiles',(SELECT jsonb_agg(to_jsonb(p) ORDER BY user_id) FROM auth.user_profile p),
		'passwords',(SELECT jsonb_agg(to_jsonb(p) ORDER BY user_id) FROM auth.password_credentials p),
		'totp',(SELECT jsonb_agg(to_jsonb(m)-'last_step' ORDER BY user_id) FROM auth.mfa_totp m),
		'provisions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY user_id) FROM auth.account_provisions p),
		'identities',(SELECT jsonb_agg(to_jsonb(i) ORDER BY issuer,subject) FROM auth.linked_identities i),
		'settings',(SELECT to_jsonb(s) FROM auth.auth_settings s)
	)::text`).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertRestoreInvalidated(t *testing.T, db *pgxpool.Pool, ctx context.Context, operations int) {
	t.Helper()
	for _, table := range []string{
		"email_verifications", "email_verification_outbox", "password_resets", "password_reset_outbox",
		"mfa_enrollments", "mfa_login_challenges", "mfa_recovery_requests", "mfa_recovery_codes", "email_bindings", "email_login_challenges",
		"email_login_outbox", "email_change_outbox", "account_invitations", "invitation_outbox", "temporary_password_credentials", "temporary_password_tokens",
	} {
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.`+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("restored proof remains", table, count, err)
		}
	}
	var safe bool
	if err := db.QueryRow(ctx, `SELECT
		NOT EXISTS(SELECT 1 FROM auth.sessions WHERE revoked_at IS NULL)
		AND NOT EXISTS(SELECT 1 FROM auth.refresh_families WHERE revoked_at IS NULL)
		AND NOT EXISTS(SELECT 1 FROM auth.email_changes WHERE state IN('pending','completed','reported'))
		AND EXISTS(SELECT 1 FROM auth.mfa_recovery_outbox WHERE failed_at IS NOT NULL AND attempts=5 AND lease IS NULL)
		AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE last_step<floor(extract(epoch FROM statement_timestamp())/30)::bigint)
		AND (SELECT count(*) FROM auth.restore_audit)=$1
		AND NOT EXISTS(SELECT 1 FROM auth.restore_audit WHERE operator_name<>session_user OR database_name<>current_database() OR users_invalidated<>(SELECT count(*) FROM auth.users))`, operations).Scan(&safe); err != nil || !safe {
		t.Fatal("restore invalidation invariant failed", err)
	}
}
