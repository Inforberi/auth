package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func TestRetentionSettingsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `CREATE ROLE auth_retention_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_retention_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_retention_runtime`)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `DROP OWNED BY auth_retention_runtime; DROP ROLE auth_retention_runtime`)
	})
	runtime := operatorPool(t, ctx, db, "auth_retention_runtime")
	repo := settingspostgres.New(runtime)
	svc, other := settingsservice.NewRetention(repo), settingsservice.NewRetention(repo)
	p := settingsdomain.RetentionPolicy{EmailReservationDays: 100, SessionDays: 100, SecurityAuditDays: 180}
	a, b := protectionPair(func() error { return svc.Initialize(ctx, p) }, func() error { return other.Initialize(ctx, p) })
	if a != nil || b != nil {
		t.Fatal("seed race", a, b)
	}
	if err := svc.Initialize(ctx, settingsdomain.RetentionPolicy{}); err != nil {
		t.Fatal("saved settings replaced by ENV", err)
	}
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('retention_operator','Operator') RETURNING id),
		p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	before, err := svc.Read(ctx, actor)
	if err != nil || before.Version != 1 || before.Policy != p {
		t.Fatal(before, err)
	}
	input := settingsservice.RetentionUpdateInput{Actor: actor, ExpectedVersion: 1, Policy: p}
	if got, err := svc.Update(ctx, input); err != nil || got != before {
		t.Fatal("no-op changed settings", got, err)
	}
	var audits int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.retention_settings_audit`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("no-op created audit", audits, err)
	}
	input.Policy = settingsdomain.RetentionPolicy{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 30}
	if _, err := svc.Update(ctx, input); !errors.Is(err, settingsdomain.ErrRetentionConfirmation) {
		t.Fatal("unconfirmed irreversible shortening", err)
	}
	input.ConfirmShortening = true
	accessExec(t, db, ctx, `ALTER TABLE auth.retention_settings_audit ADD CONSTRAINT reject_settings CHECK(version<2) NOT VALID`)
	if _, err := svc.Update(ctx, input); err == nil {
		t.Fatal("failed audit committed settings")
	}
	if got, err := svc.Read(ctx, actor); err != nil || got != before {
		t.Fatal("audit rollback changed settings", got, err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.retention_settings_audit DROP CONSTRAINT reject_settings`)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.retention_settings SET session_days=0`)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.retention_settings SET security_audit_days=106752`)

	// The worker's ENV values deliberately differ; only the saved SQL policy controls cleanup.
	f := newStatusFixture(t, db, ctx, "saved-retention")
	if _, err := deleteFixture(ctx, f, 1); err != nil {
		t.Fatal(err)
	}
	ageDeletion(t, db, ctx, f.user)
	token := strings.Repeat("e", 64)
	accessExec(t, db, ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
		VALUES($1,$2,1,clock_timestamp()-interval '50 days',clock_timestamp()-interval '40 days',clock_timestamp()-interval '39 days','','')`, token, actor.UserID)
	accessExec(t, db, ctx, `INSERT INTO auth.auth_settings_audit(actor_id,version,previous_policy,next_policy,created_at)
		VALUES($1,777,'{}','{}',clock_timestamp()-interval '40 days')`, actor.UserID)
	var expires, absolute time.Time
	if err := db.QueryRow(ctx, `SELECT expires_at,absolute_expires_at FROM auth.sessions WHERE token_hash=$1`, actor.TokenHash).Scan(&expires, &absolute); err != nil {
		t.Fatal(err)
	}
	worker := accountservice.NewRetention(accountpostgres.New(runtime), accountservice.RetentionConfig{
		EmailReservationDays: 1, SessionDays: 1, SecurityAuditDays: 1, BatchSize: 1, Interval: time.Minute,
	}).WithSettings(other)
	if _, err := worker.Purge(ctx); err != nil || contactCount(t, db, ctx, f.user) != 1 {
		t.Fatal("used ENV policy", err)
	}
	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE token_hash=$1)`, token).Scan(&exists); err != nil || !exists {
		t.Fatal("old session deleted before saved deadline", err)
	}
	a, b = protectionPair(func() error { _, err := svc.Update(ctx, input); return err }, func() error { _, err := other.Update(ctx, input); return err })
	firstWon := a == nil && errors.Is(b, settingsdomain.ErrPolicyConflict)
	secondWon := b == nil && errors.Is(a, settingsdomain.ErrPolicyConflict)
	if !firstWon && !secondWon {
		t.Fatal("concurrent updates", a, b)
	}
	if current, err := other.Current(ctx); err != nil || current != input.Policy {
		t.Fatal("second instance stale", current, err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.retention_settings_audit WHERE version=2`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("not one atomic audit", audits, err)
	}
	accessExec(t, db, ctx, `UPDATE auth.retention_settings_audit SET created_at=clock_timestamp()-interval '40 days'`)
	if _, err := worker.Purge(ctx); err != nil || contactCount(t, db, ctx, f.user) != 0 {
		t.Fatal("next batch did not apply saved policy", err)
	}
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE token_hash=$1)`, token).Scan(&exists); err != nil || exists {
		t.Fatal("expired session not cleaned", err)
	}
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.retention_settings_audit) OR EXISTS(SELECT 1 FROM auth.auth_settings_audit WHERE version=777)`).Scan(&exists); err != nil || exists {
		t.Fatal("audit retention not applied", err)
	}
	var nextExpires, nextAbsolute time.Time
	if err := db.QueryRow(ctx, `SELECT expires_at,absolute_expires_at FROM auth.sessions WHERE token_hash=$1`, actor.TokenHash).Scan(&nextExpires, &nextAbsolute); err != nil || nextExpires != expires || nextAbsolute != absolute {
		t.Fatal("active session deadlines changed", err)
	}

	input.ExpectedVersion = 2
	accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE token_hash=$1`, actor.TokenHash)
	if _, err := svc.Update(ctx, input); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
		t.Fatal("no-op bypassed MFA", err)
	}
	if _, err := svc.Read(ctx, actor); err != nil {
		t.Fatal("reading requires fresh proof", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash)
	accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE permission_key='auth.settings.manage'`)
	if _, err := svc.Update(ctx, input); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("missing current permission", err)
	}
	if _, err := svc.Read(ctx, actor); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("read leaked settings", err)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.retention_settings;
		INSERT INTO auth.initial_setup(singleton,initialized_at,administrator_id) VALUES(true,clock_timestamp(),gen_random_uuid())`)
	if _, err := worker.Purge(ctx); !errors.Is(err, settingsdomain.ErrNotInitialized) {
		t.Fatal("worker fell back to ENV after lost row", err)
	}
	if err := svc.Initialize(ctx, p); !errors.Is(err, settingsdomain.ErrNotInitialized) {
		t.Fatal("initialized installation silently reseeded", err)
	}
}
