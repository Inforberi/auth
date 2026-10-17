package postgres

import (
	"context"
	"errors"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func TestAuthProfileTransitionsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	actor := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, actor.UserID)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('profile_operator','Operator') RETURNING id),
		p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	accessExec(t, db, ctx, `CREATE ROLE auth_profile_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_profile_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_profile_runtime`)
	t.Cleanup(func() { accessExec(t, db, ctx, `DROP OWNED BY auth_profile_runtime; DROP ROLE auth_profile_runtime`) })
	runtime := operatorPool(t, ctx, db, "auth_profile_runtime")
	repo := settingspostgres.NewWithRuntime(runtime, settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true})
	svc := settingsservice.New(repo)
	before, err := repo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	closed := before.Policy
	closed.Methods = settingsdomain.PublicMethods{}
	input := settingsservice.UpdateInput{Actor: actor, ExpectedVersion: before.Version, Policy: closed}
	assertUnchanged := func() {
		t.Helper()
		got, err := repo.Load(ctx)
		var audits int
		if err != nil || got != before {
			t.Fatal("rejected transition changed policy", got, err)
		}
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.auth_settings_audit`).Scan(&audits); err != nil || audits != 0 {
			t.Fatal("rejected transition wrote audit", audits, err)
		}
	}
	if _, err := svc.Update(ctx, input); !errors.Is(err, accountdomain.ErrLastAdministrator) {
		t.Fatal("custom operator was counted as a protected super-admin", err)
	}
	assertUnchanged()
	backup := newStatusFixture(t, db, ctx, "profile-backup")
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'access.assignments.manage')`, role)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, backup.user, role)
	// Membership alone, even with a password, is not a usable private path.
	if _, err := svc.Update(ctx, input); !errors.Is(err, accountdomain.ErrLastAdministrator) {
		t.Fatal("factor-less unverified backup accepted", err)
	}
	assertUnchanged()
	prepareUsableAdministrator(t, db, ctx, backup.user)
	accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, backup.user)
	if _, err := svc.Update(ctx, input); !errors.Is(err, accountdomain.ErrLastAdministrator) {
		t.Fatal("blocked backup accepted", err)
	}
	assertUnchanged()
	accessExec(t, db, ctx, `UPDATE auth.users SET status='active' WHERE id=$1`, backup.user)
	closedResult, err := svc.Update(ctx, input)
	if err != nil || closedResult.Policy != closed {
		t.Fatal("ready protected admin did not allow admin-only", closedResult, err)
	}
	// Existing sessions remain valid; profile switching is not logout-all.
	if _, err := svc.Read(ctx, actor); err != nil {
		t.Fatal("switch invalidated actor session", err)
	}
	input.ExpectedVersion = closedResult.Version
	accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, backup.user)
	if _, err := svc.Update(ctx, input); err != nil {
		t.Fatal("current no-op blocked recovery", err)
	}
	input.Policy.Methods.Password = true
	opened, err := svc.Update(ctx, input)
	if err != nil || !opened.Policy.Methods.Password {
		t.Fatal("opening a recovery path was blocked", err)
	}
	input.ExpectedVersion = opened.Version
	input.Policy.PasswordEmailVerification = settingsdomain.VerificationRequired
	if _, err := svc.Update(ctx, input); !errors.Is(err, accountdomain.ErrLastAdministrator) {
		t.Fatal("verification tightening bypassed readiness", err)
	}
	// Readiness must be checked after waiting for the shared Access serialization.
	accessExec(t, db, ctx, `UPDATE auth.users SET status='active' WHERE id=$1`, backup.user)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(734013981)`); err != nil {
		t.Fatal(err)
	}
	failure := make(chan error, 1)
	go func() { _, err := svc.Update(ctx, input); failure <- err }()
	waitForAdministrativeLock(t, db, ctx)
	if _, err := tx.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, backup.user); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-failure; !errors.Is(err, accountdomain.ErrLastAdministrator) {
		t.Fatal("transition used pre-lock readiness", err)
	}
	if got, err := repo.Load(ctx); err != nil || got != opened {
		t.Fatal("failed lock-wait transition changed state", got, err)
	}
	checkMFASelfStatus(t, db, runtime, ctx)
}
