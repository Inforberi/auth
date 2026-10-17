package postgres

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestProviderSettingsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `CREATE ROLE auth_provider_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_provider_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_provider_runtime`)
	t.Cleanup(func() { accessExec(t, db, ctx, `DROP OWNED BY auth_provider_runtime; DROP ROLE auth_provider_runtime`) })
	runtime := operatorPool(t, ctx, db, "auth_provider_runtime")
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	google, err := secretbox.NewScoped(root, "provider-google:v1")
	if err != nil {
		t.Fatal(err)
	}
	telegram, err := secretbox.NewScoped(root, "provider-telegram:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := settingspostgres.New(runtime)
	svc := settingsservice.NewProviders(repo, google, telegram)
	other := settingsservice.NewProviders(repo, google, telegram)
	a, b := protectionPair(func() error {
		return svc.Initialize(ctx, "google", "fixture.apps.googleusercontent.com", "first", true)
	}, func() error {
		return other.Initialize(ctx, "google", "fixture.apps.googleusercontent.com", "second", true)
	})
	if a != nil || b != nil {
		t.Fatal("seed race", a, b)
	}
	if err := svc.Initialize(ctx, "telegram", "123", "telegram-secret", true); err != nil {
		t.Fatal(err)
	}
	if err := svc.Initialize(ctx, "google", "invalid", "invalid\x00seed", true); err != nil {
		t.Fatal("ENV replaced saved provider", err)
	}
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('provider_operator','Operator') RETURNING id),
		p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	before, err := svc.Read(ctx, actor, "google")
	if err != nil || before.Version != 1 || !before.SecretSet {
		t.Fatal(before, err)
	}
	input := settingsservice.ProviderUpdateInput{Actor: actor, Provider: "google", ClientID: before.ClientID, ExpectedVersion: 1}
	if got, err := svc.Update(ctx, input); err != nil || got != before {
		t.Fatal("no-op changed credentials", got, err)
	}
	accounts := accountpostgres.New(runtime)
	key := accountdomain.IdentityKey{Issuer: settingsdomain.ProviderIssuer("google"), Subject: "google-owner", ProviderVersion: 1}
	user, err := accounts.ResolveIdentityAccount(ctx, key, true)
	if err != nil {
		t.Fatal(err)
	}
	proof := mfaservice.PrimaryProof{UserID: user.ID, AuthVersion: 1, Method: "oidc", Issuer: key.Issuer, Reference: key.Subject, VerifiedAt: time.Now().UTC(), ProviderVersion: 1}
	now := time.Now().UTC()
	sessions := sessionpostgres.New(runtime)
	params := sessionservice.CreateSessionParams{UserID: user.ID, AuthVersion: 1, TokenHash: strings.Repeat("c", 64), CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour), PrimaryProof: &proof}
	if _, err := sessions.CreateSession(ctx, params); err != nil {
		t.Fatal("current provider proof rejected", err)
	}
	rotated := "rotated-secret"
	input.Secret = &rotated
	accessExec(t, db, ctx, `ALTER TABLE auth.provider_settings_audit ADD CONSTRAINT reject_rotation CHECK(version<2) NOT VALID`)
	if _, err := svc.Update(ctx, input); err == nil {
		t.Fatal("audit failure committed secret")
	}
	if got, err := svc.Read(ctx, actor, "google"); err != nil || got != before {
		t.Fatal("failed rotation changed version", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.provider_settings_audit DROP CONSTRAINT reject_rotation`)
	left, right := protectionPair(func() error { _, err := svc.Update(ctx, input); return err }, func() error { _, err := other.Update(ctx, input); return err })
	firstWon := left == nil && errors.Is(right, settingsdomain.ErrPolicyConflict)
	secondWon := right == nil && errors.Is(left, settingsdomain.ErrPolicyConflict)
	if !firstWon && !secondWon {
		t.Fatal("lost concurrent rotation", left, right)
	}
	_, password, err := other.Credentials(ctx, "google")
	if err != nil || password != rotated {
		t.Fatal("second instance retained old secret", err)
	}
	if _, err := sessions.FindSession(ctx, params.TokenHash); err != nil {
		t.Fatal("rotation revoked existing session", err)
	}
	params.TokenHash = tokengenerate.New().Hash("stale-provider-session")
	if _, err := sessions.CreateSession(ctx, params); !errors.Is(err, settingsdomain.ErrProviderRevision) {
		t.Fatal("stale proof issued session", err)
	}
	proof.ProviderVersion = 0
	if _, err := sessions.CreateSession(ctx, params); !errors.Is(err, settingsdomain.ErrProviderRevision) {
		t.Fatal("managed provider accepted an unversioned proof", err)
	}
	proof.ProviderVersion = 1
	stale := key
	stale.Subject = "stale-registration"
	if _, err := accounts.ResolveIdentityAccount(ctx, stale, true); !errors.Is(err, settingsdomain.ErrProviderRevision) {
		t.Fatal("stale credentials created identity", err)
	}
	var orphans int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users u WHERE NOT EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=u.id)
		AND NOT EXISTS(SELECT 1 FROM auth.linked_identities WHERE user_id=u.id)`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatal("stale registration left orphan", orphans, err)
	}
	proof.ProviderVersion = 2
	if _, err := sessions.CreateSession(ctx, params); err != nil {
		t.Fatal("fresh proof after rotation", err)
	}
	// MFA captures this revision as part of the primary proof; rotation must reject completion before consuming codes.
	f := newMFALoginFixture(t, db, ctx, "provider-revision")
	accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) VALUES($1,'mfa-owner',$2)`, key.Issuer, f.user)
	f.proof.Method, f.proof.Issuer, f.proof.Reference, f.proof.ProviderVersion = "oidc", key.Issuer, "mfa-owner", 2
	completion := f.start(t, ctx)
	input.ExpectedVersion = 2
	if _, err := svc.Update(ctx, input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.login.Complete(ctx, completion); !errors.Is(err, settingsdomain.ErrProviderRevision) {
		t.Fatal("stale primary completed MFA", err)
	}
	var codes int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1`, f.user).Scan(&codes); err != nil || codes != 10 {
		t.Fatal("denial consumed factor", codes, err)
	}
	// Client ID cannot rebind existing users, even while public login is disabled.
	accessExec(t, db, ctx, `UPDATE auth.auth_settings SET google_enabled=false`)
	input.ExpectedVersion = 3
	input.ClientID = "replacement.apps.googleusercontent.com"
	if _, err := svc.Update(ctx, input); !errors.Is(err, settingsdomain.ErrProviderClientBound) {
		t.Fatal("existing identities accepted a new client ID", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.auth_settings SET telegram_enabled=false`)
	empty := ""
	if _, err := svc.Update(ctx, settingsservice.ProviderUpdateInput{Actor: actor, Provider: "telegram", ClientID: "123", ExpectedVersion: 1, Secret: &empty}); err != nil {
		t.Fatal("disabled provider secret could not be cleared", err)
	}
	policyRepo := settingspostgres.NewWithRuntime(runtime, settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}, settingsdomain.TokenIssuance{SessionExchange: true, Native: true})
	snapshot, err := policyRepo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Policy.Methods.Telegram = true
	if _, err := settingsservice.New(policyRepo).Update(ctx, settingsservice.UpdateInput{Actor: actor, ExpectedVersion: snapshot.Version, Policy: snapshot.Policy}); !errors.Is(err, settingsdomain.ErrMethodNotReady) {
		t.Fatal("enabled provider without credentials", err)
	}
	var audit string
	if err := db.QueryRow(ctx, `SELECT string_agg(previous_configuration::text||next_configuration::text,'') FROM auth.provider_settings_audit`).Scan(&audit); err != nil || strings.Contains(audit, rotated) {
		t.Fatal("secret in audit", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=NULL WHERE token_hash=$1`, actor.TokenHash)
	input.ClientID = before.ClientID
	if _, err := svc.Update(ctx, input); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
		t.Fatal("rotation missing MFA", err)
	}
	if _, err := svc.Read(ctx, actor, "google"); err != nil {
		t.Fatal("read needs fresh proof", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.provider_settings SET secret=decode(repeat('00',48),'hex') WHERE provider='google'`)
	if _, _, err := svc.Credentials(ctx, "google"); err == nil {
		t.Fatal("corrupt secret fell back to ENV")
	}
	accessExec(t, db, ctx, `DELETE FROM auth.provider_settings WHERE provider='google';
		INSERT INTO auth.initial_setup(singleton,initialized_at,administrator_id) VALUES(true,clock_timestamp(),gen_random_uuid())`)
	if err := svc.Initialize(ctx, "google", before.ClientID, "env-secret", true); !errors.Is(err, settingsdomain.ErrNotInitialized) {
		t.Fatal("lost managed record silently reseeded", err)
	}
}
