package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestAuthSettingsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `DELETE FROM auth.auth_settings`)
	accessExec(t, db, ctx, `CREATE ROLE auth_settings_runtime LOGIN PASSWORD 'synthetic-settings-runtime';
		GRANT USAGE ON SCHEMA auth TO auth_settings_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_settings_runtime`)
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down"); accessExec(t, db, ctx, `DROP ROLE auth_settings_runtime`) })
	cfg := db.Config()
	cfg.ConnConfig.User = "auth_settings_runtime"
	cfg.ConnConfig.Password = "synthetic-settings-runtime"
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	repo := settingspostgres.NewWithRuntime(runtime, settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}, settingsdomain.TokenIssuance{})
	svc := settingsservice.New(repo)
	if _, err := repo.Load(ctx); !errors.Is(err, settingsdomain.ErrNotInitialized) {
		t.Fatal("missing row is not a default profile", err)
	}
	seed := (config.Config{}).InitialAuthPolicy()
	// Competing initializers must agree on the one committed first-install source.
	other := seed
	other.Registration.Enabled = false
	results := make(chan settingsdomain.Snapshot, 2)
	failures := make(chan error, 2)
	for _, policy := range []settingsdomain.Policy{seed, other} {
		go func() { result, err := svc.Initialize(ctx, policy); results <- result; failures <- err }()
	}
	a, b := <-results, <-results
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if a != b || a.Version != 1 {
		t.Fatal("initializers overwrote each other", a, b)
	}
	if result, err := svc.Initialize(ctx, settingsdomain.Policy{}); err != nil || result != a {
		t.Fatal("ENV seed replaced stored settings", result, err)
	}
	actor := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, actor.UserID)
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'auth.settings.manage'),($1,'access.assignments.manage')`, role)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, actor.UserID, role)
	if result, err := svc.Read(ctx, actor); err != nil || result != a {
		t.Fatal(result, err)
	}
	checkSettingsRuntimeHTTP(t, runtime, ctx, actor, a)
	ordinary := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('settings_custom','Settings custom') RETURNING id),
		p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, ordinary.UserID)
	input := settingsservice.UpdateInput{Actor: actor, ExpectedVersion: 1, Policy: a.Policy}
	input.Policy.PasswordEmailVerification = settingsdomain.VerificationRequired
	bad := input
	bad.Actor = ordinary
	if got, err := svc.Read(ctx, ordinary); err != nil || got != a {
		t.Fatal("delegated permission could not read settings", got, err)
	}
	bad.Policy = a.Policy
	if got, err := svc.Update(ctx, bad); err != nil || got != a {
		t.Fatal("delegated current no-op failed", got, err)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, ordinary.UserID)
	if _, err := svc.Read(ctx, ordinary); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("read survived permission revoke", err)
	}
	if _, err := svc.Update(ctx, bad); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("write survived permission revoke", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE user_id=$1`, actor.UserID)
	if _, err := svc.Read(ctx, actor); err != nil {
		t.Fatal("read unexpectedly requires fresh proof", err)
	}
	if _, err := svc.Update(ctx, input); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
		t.Fatal("proof-less write", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp() WHERE user_id=$1`, actor.UserID)
	current, err := svc.Update(ctx, input)
	if err != nil || current.Version != 2 || current.Policy != input.Policy {
		t.Fatal(current, err)
	}
	if _, err := svc.Update(ctx, input); !errors.Is(err, settingsdomain.ErrPolicyConflict) {
		t.Fatal("stale write accepted", err)
	}
	input.ExpectedVersion = 2
	if got, err := svc.Update(ctx, input); err != nil || got != current {
		t.Fatal("current no-op changed revision", got, err)
	}
	var audits int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.auth_settings_audit WHERE actor_id=$1`, actor.UserID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit/no-op", audits, err)
	}
	checkSettingsAuditRollback(t, db, ctx, svc, input)
	first, second := input, input
	first.Policy.PasswordEmailVerification = settingsdomain.VerificationDisabled
	second.Policy.PasswordEmailVerification = settingsdomain.VerificationOptional
	left, right := protectionPair(func() error { _, err := svc.Update(ctx, first); return err }, func() error { _, err := svc.Update(ctx, second); return err })
	firstWon := left == nil && errors.Is(right, settingsdomain.ErrPolicyConflict)
	secondWon := right == nil && errors.Is(left, settingsdomain.ErrPolicyConflict)
	if !firstWon && !secondWon {
		t.Fatal("concurrent settings lost update", left, right)
	}
	current, err = svc.Read(ctx, actor)
	if err != nil || current.Version != 3 {
		t.Fatal(current, err)
	}
	checkSettingsAuthorityWait(t, db, ctx, svc, actor, role, current)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.auth_settings SET password_email_verification='invalid' WHERE singleton`)
	expectSQLState(t, db, ctx, "23514", `INSERT INTO auth.auth_settings(singleton,password_enabled,email_otp_enabled,google_enabled,telegram_enabled,registration_enabled,google_registration_enabled,telegram_registration_enabled,password_email_verification) VALUES(false,false,false,false,false,false,false,false,'optional')`)
	accessExec(t, db, ctx, `UPDATE auth.auth_settings_audit SET created_at=clock_timestamp()-interval '181 days' WHERE version=2`)
	if _, err := accountpostgres.New(runtime).PurgeRetention(ctx, retentionPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.auth_settings_audit`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("settings audit not covered by retention", audits, err)
	}
	if result, err := repo.Load(ctx); err != nil || result != current {
		t.Fatal("retention changed current settings", result, err)
	}
	// A lost row after setup is not permission to reset the saved configuration from ENV.
	checkSavedTokenSwitches(t, db, ctx, actor)
	accessExec(t, db, ctx, `DELETE FROM auth.auth_settings;
		INSERT INTO auth.initial_setup(singleton,initialized_at,administrator_id) VALUES(true,clock_timestamp(),gen_random_uuid())`)
	if _, err := svc.Initialize(ctx, seed); !errors.Is(err, settingsdomain.ErrNotInitialized) {
		t.Fatal("initialized installation silently reset", err)
	}
}

func checkSettingsAuditRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *settingsservice.Service, input settingsservice.UpdateInput) {
	t.Helper()
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_settings_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic settings audit failure'; END $$;
		CREATE TRIGGER reject_settings_audit BEFORE INSERT ON auth.auth_settings_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_settings_audit()`)
	before, err := svc.Read(ctx, input.Actor)
	if err != nil {
		t.Fatal(err)
	}
	input.Policy.Registration.Enabled = !input.Policy.Registration.Enabled
	if _, err := svc.Update(ctx, input); err == nil {
		t.Fatal("audit failure committed settings")
	}
	if after, err := svc.Read(ctx, input.Actor); err != nil || after != before {
		t.Fatal("partial policy commit", after, err)
	}
	accessExec(t, db, ctx, `DROP TRIGGER reject_settings_audit ON auth.auth_settings_audit; DROP FUNCTION auth.reject_settings_audit()`)
}

func checkSettingsAuthorityWait(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *settingsservice.Service, actor accessservice.Principal, role string, current settingsdomain.Snapshot) {
	t.Helper()
	for _, kind := range []string{"permission", "membership"} {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Preserve the assertion error; commit closes the transaction.
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			t.Fatal(err)
		}
		query := `DELETE FROM auth.role_permissions WHERE role_id=$1 AND permission_key='auth.settings.manage'`
		if kind == "membership" {
			query = `DELETE FROM auth.user_roles WHERE role_id=$1`
		}
		if _, err := tx.Exec(ctx, query, role); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := svc.Update(ctx, settingsservice.UpdateInput{Actor: actor, ExpectedVersion: current.Version, Policy: current.Policy})
			result <- err
		}()
		poll := time.NewTicker(10 * time.Millisecond)
		waiting := false
		until := time.Now().Add(2 * time.Second)
		for time.Now().Before(until) {
			if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='auth_settings_runtime' AND wait_event='advisory')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case <-poll.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		poll.Stop()
		if !waiting {
			t.Fatal("settings write did not wait", kind)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if !errors.Is(err, accessdomain.ErrForbidden) {
				t.Fatal("stale settings authority accepted", kind, err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if _, err := svc.Read(ctx, actor); !errors.Is(err, accessdomain.ErrForbidden) {
			t.Fatal("settings read used stale authority", kind, err)
		}
		accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'auth.settings.manage') ON CONFLICT DO NOTHING`, role)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, actor.UserID, role)
		if got, err := svc.Read(ctx, actor); err != nil || got != current {
			t.Fatal("denied write changed settings", got, err)
		}
	}
}
