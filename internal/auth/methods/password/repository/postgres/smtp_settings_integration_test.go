package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestSMTPSettingsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `CREATE ROLE auth_smtp_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_smtp_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_smtp_runtime`)
	t.Cleanup(func() { accessExec(t, db, ctx, `DROP OWNED BY auth_smtp_runtime; DROP ROLE auth_smtp_runtime`) })
	runtime := operatorPool(t, ctx, db, "auth_smtp_runtime")
	repo := settingspostgres.New(runtime)
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "smtp-settings:v1")
	if err != nil {
		t.Fatal(err)
	}
	initial := settingsdomain.SMTPConfig{Host: "smtp.example.com", Port: 587, Username: "owner", From: "auth@example.com", Domain: "example.com", RequireTLS: true}
	probeCalls := 0
	probe := func(ctx context.Context, c settingsdomain.SMTPConfig, password string) error {
		probeCalls++
		if c != initial {
			t.Error("probe loaded wrong configuration")
		}
		if password != "rotated-secret" {
			t.Error("probe loaded wrong secret")
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var unlocked bool
		err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(734013981)`).Scan(&unlocked)
		if err != nil {
			return err
		}
		if !unlocked {
			t.Error("network test held Access lock")
		}
		return nil
	}
	makeService := func() *settingsservice.SMTP {
		s, err := settingsservice.NewSMTP(repo, cipher, probe, mfaTestLimit{}, []string{"smtp.example.com:587", "backup.example.com:587"}, true)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	svc, otherInstance := makeService(), makeService()
	a, b := protectionPair(func() error { return svc.Initialize(ctx, initial, "initial-secret") }, func() error { return otherInstance.Initialize(ctx, initial, "other-seed") })
	if a != nil || b != nil {
		t.Fatal("first-install race", a, b)
	}
	_, savedPassword, err := svc.Credentials(ctx)
	if err != nil || savedPassword != "initial-secret" && savedPassword != "other-seed" {
		t.Fatal("seed missing", err)
	}
	if err := svc.Initialize(ctx, settingsdomain.SMTPConfig{}, "invalid\x00seed"); err != nil {
		t.Fatal("saved settings replaced by ENV", err)
	}
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('smtp_operator','SMTP operator') RETURNING id),
		p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	before, err := svc.Read(ctx, actor)
	if err != nil || before.Version != 1 || !before.PasswordSet {
		t.Fatal(before, err)
	}
	input := settingsservice.SMTPUpdateInput{Actor: actor, ExpectedVersion: 1, Config: initial}
	if current, err := svc.Update(ctx, input); err != nil || current != before {
		t.Fatal("no-op changed version", current, err)
	}
	bad := input
	bad.Config.Host = "backup.example.com"
	if _, err := svc.Update(ctx, bad); !errors.Is(err, settingsdomain.ErrInvalidSMTP) {
		t.Fatal("secret silently moved to new destination", err)
	}
	bad = input
	empty := ""
	bad.Password = &empty
	if _, err := svc.Update(ctx, bad); !errors.Is(err, settingsdomain.ErrInvalidSMTP) {
		t.Fatal("authenticated SMTP accepted an empty password", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.smtp_settings_audit ADD CONSTRAINT reject_smtp_rotation CHECK(version<2) NOT VALID`)
	rotated := "rotated-secret"
	input.Password = &rotated
	if _, err := svc.Update(ctx, input); err == nil {
		t.Fatal("audit failure committed secret rotation")
	}
	_, afterFailure, err := svc.Credentials(ctx)
	if err != nil || afterFailure != savedPassword {
		t.Fatal("rollback replaced secret", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.smtp_settings_audit DROP CONSTRAINT reject_smtp_rotation`)
	left, right := protectionPair(func() error { _, err := svc.Update(ctx, input); return err }, func() error { _, err := otherInstance.Update(ctx, input); return err })
	firstWon := left == nil && errors.Is(right, settingsdomain.ErrPolicyConflict)
	secondWon := right == nil && errors.Is(left, settingsdomain.ErrPolicyConflict)
	if !firstWon && !secondWon {
		t.Fatal("lost concurrent update", left, right)
	}
	_, freshPassword, err := otherInstance.Credentials(ctx)
	if err != nil || freshPassword != rotated {
		t.Fatal("other instance retained old secret", err)
	}
	if err := svc.TestConnection(ctx, actor, 2); err != nil || probeCalls != 1 {
		t.Fatal("connection test", err)
	}
	if err := svc.TestConnection(ctx, actor, 1); !errors.Is(err, settingsdomain.ErrPolicyConflict) || probeCalls != 1 {
		t.Fatal("stale test reached network", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE token_hash=$1`, actor.TokenHash)
	if _, err := svc.Read(ctx, actor); err != nil {
		t.Fatal("read requires fresh proof", err)
	}
	input.ExpectedVersion = 2
	if _, err := svc.Update(ctx, input); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
		t.Fatal("write missing MFA", err)
	}
	if err := svc.TestConnection(ctx, actor, 2); !errors.Is(err, accessdomain.ErrFreshAuthRequired) || probeCalls != 1 {
		t.Fatal("test missing MFA", err)
	}
	var audit string
	if err := db.QueryRow(ctx, `SELECT previous_configuration::text||next_configuration::text FROM auth.smtp_settings_audit`).Scan(&audit); err != nil || strings.Contains(audit, "secret") || strings.Contains(audit, "password\"") {
		t.Fatal("secret in audit", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.smtp_settings_audit SET created_at=clock_timestamp()-interval '181 days'`)
	if _, err := accountpostgres.New(runtime).PurgeRetention(ctx, retentionPolicy()); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.smtp_settings_audit`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("SMTP audit not purged", remaining, err)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, actor.UserID)
	if _, err := svc.Read(ctx, actor); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("revoked read allowed", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.smtp_settings SET password=decode(repeat('00',48),'hex')`)
	if _, _, err := svc.Credentials(ctx); err == nil {
		t.Fatal("tampered secret fell back to ENV")
	}
	accessExec(t, db, ctx, `DELETE FROM auth.smtp_settings;
		INSERT INTO auth.initial_setup(singleton,initialized_at,administrator_id) VALUES(true,clock_timestamp(),gen_random_uuid())`)
	if err := svc.Initialize(ctx, initial, "fresh-env-secret"); !errors.Is(err, settingsdomain.ErrNotInitialized) {
		t.Fatal("lost saved settings silently reseeded", err)
	}
}
