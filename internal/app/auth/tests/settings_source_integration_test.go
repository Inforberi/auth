package auth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	providers "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsretention "github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/service"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	smtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	authschema "github.com/Inforberi/financial-intelligence/migrations/auth"
)

func sourceInput() configuration.Input {
	return configuration.Input{
		Mode:         settingsdomain.SourceENV,
		Policy:       settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled},
		Retention:    settingsdomain.RetentionPolicy{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180},
		SMTP:         settingsdomain.SMTPConfig{Host: "smtp.example.com", Port: 587, From: "auth@example.com", Domain: "example.com", RequireTLS: true},
		SMTPPassword: "synthetic-only", AllowedSMTP: []string{"smtp.example.com:587"}, RequireTLS: true,
		Providers: [2]configuration.ProviderInput{{Name: "google"}, {Name: "telegram"}},
	}
}

func startSource(t *testing.T, ctx context.Context, db *pgxpool.Pool, input configuration.Input) (configuration.Lease, error) {
	t.Helper()
	return startSourceWithKey(t, ctx, db, input, base64.StdEncoding.EncodeToString(make([]byte, 32)))
}

func startSourceWithKey(t *testing.T, ctx context.Context, db *pgxpool.Pool, input configuration.Input, key string) (configuration.Lease, error) {
	t.Helper()
	smtp, err := secretbox.NewScoped(key, "smtp-settings:v1")
	if err != nil {
		t.Fatal(err)
	}
	google, err := secretbox.NewScoped(key, "provider-google:v1")
	if err != nil {
		t.Fatal(err)
	}
	telegram, err := secretbox.NewScoped(key, "provider-telegram:v1")
	if err != nil {
		t.Fatal(err)
	}
	return configuration.Start(ctx, settingspostgres.New(db), input, key, smtp, map[string]settingsservice.ProviderCipher{"google": google, "telegram": telegram})
}

func TestSettingsSourceEnvironmentSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	if _, err := db.Exec(ctx, authschema.InitialAuth()+"\n"+authschema.StandaloneMigrations()+"\n"+authschema.PlatformUserLifecycle); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	input := sourceInput()
	first, err := startSource(t, ctx, db, input)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := startSource(t, ctx, db, input)
	if err != nil {
		t.Fatal("same-profile replica rejected", err)
	}
	defer second.Close()
	if lease, err := startSourceWithKey(t, ctx, db, input, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))); !errors.Is(err, settingsdomain.ErrSourceConflict) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("root key was replaced by ENV sync", err)
	}
	var events int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.settings_source_audit`).Scan(&events); err != nil || events != 1 {
		t.Fatal("restart rewrote source", events, err)
	}
	changed := input
	changed.Retention.SessionDays = 60
	if lease, err := startSource(t, ctx, db, changed); !errors.Is(err, settingsdomain.ErrSourceConflict) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("live ENV replacement accepted", err)
	}
	actor := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, actor.UserID)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('source_manager','Source manager') RETURNING id),p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r) INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	svc := settingsservice.New(settingspostgres.NewWithRuntime(db, settingsdomain.PublicMethods{Password: true}, settingsdomain.TokenIssuance{}))
	snapshot, err := svc.Read(ctx, actor)
	if err != nil || snapshot.Source != settingsdomain.SourceENV {
		t.Fatal("source metadata", snapshot, err)
	}
	if _, err := svc.Update(ctx, settingsservice.UpdateInput{Actor: actor, ExpectedVersion: snapshot.Version, Policy: snapshot.Policy}); !errors.Is(err, settingsdomain.ErrSourceReadOnly) {
		t.Fatal("policy write allowed", err)
	}
	if _, err := settingsretention.NewRetention(settingspostgres.New(db)).Update(ctx, settingsretention.RetentionUpdateInput{Actor: actor, ExpectedVersion: 1, Policy: input.Retention}); !errors.Is(err, settingsdomain.ErrSourceReadOnly) {
		t.Fatal("retention write allowed", err)
	}
	repo := settingspostgres.New(db)
	for name, change := range map[string]func() error{
		"smtp": func() error {
			_, err := repo.UpdateSMTP(ctx, smtp.SMTPUpdate{Actor: actor, ExpectedVersion: 1, Config: input.SMTP})
			return err
		},
		"provider": func() error {
			_, err := repo.UpdateProvider(ctx, providers.ProviderUpdate{Actor: actor, Provider: "google", ExpectedVersion: 1})
			return err
		},
		"mfa": func() error {
			_, err := repo.UpdateMFAPolicy(ctx, settingsservice.MFAUpdateInput{Actor: actor, MFAChange: settingsservice.MFAChange{ExpectedVersion: 1, Policy: settingsdomain.MFAPolicy{Mode: settingsdomain.MFAAdministrators}}}, true)
			return err
		},
		"telegram side effect": func() error { _, err := repo.AuthorizeTelegramBotUpdate(ctx, actor, 1); return err },
	} {
		if err := change(); !errors.Is(err, settingsdomain.ErrSourceReadOnly) {
			t.Fatal(name, err)
		}
	}
	ordinary := accessPrincipal(t, db, ctx)
	if _, err := svc.Update(ctx, settingsservice.UpdateInput{Actor: ordinary, ExpectedVersion: 1, Policy: snapshot.Policy}); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("source disclosed before authority", err)
	}
	h := settingshttp.New(svc, settingsdomain.PublicMethods{Password: true}, zap.NewNop())
	request := httptest.NewRequest("GET", "https://localhost/api/v1/admin/auth/settings", nil)
	request = request.WithContext(sessionhttp.SetAuthContext(ctx, sessionhttp.Auth{UserID: actor.UserID, TokenHash: actor.TokenHash}))
	response := httptest.NewRecorder()
	h.Read(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"readOnly":true`) || strings.Contains(response.Body.String(), "synthetic-only") {
		t.Fatal("metadata response", response.Code)
	}
	body, err := json.Marshal(map[string]any{"expectedVersion": snapshot.Version, "policy": settingshttp.SettingsResponseFrom(snapshot, settingsdomain.PublicMethods{Password: true}).Policy})
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest("POST", "https://localhost/api/v1/admin/auth/settings", bytes.NewReader(body))
	post.Header.Set("Content-Type", "application/json")
	post = post.WithContext(sessionhttp.SetAuthContext(ctx, sessionhttp.Auth{UserID: actor.UserID, TokenHash: actor.TokenHash}))
	out := httptest.NewRecorder()
	h.Update(out, post)
	if out.Code != 409 || !strings.Contains(out.Body.String(), "settings_source_read_only") {
		t.Fatal("HTTP read-only contract", out.Code)
	}
	first.Close()
	second.Close()
	third, err := startSource(t, ctx, db, changed)
	if err != nil {
		t.Fatal("maintenance resync", err)
	}
	defer third.Close()
	var days int
	if err := db.QueryRow(ctx, `SELECT session_days FROM auth.retention_settings`).Scan(&days); err != nil || days != 60 {
		t.Fatal("ENV not synchronized", days, err)
	}
	var smtpVersion int64
	if err := db.QueryRow(ctx, `SELECT version FROM auth.smtp_settings`).Scan(&smtpVersion); err != nil || smtpVersion != 1 {
		t.Fatal("unrelated secret rotated", smtpVersion, err)
	}
	third.Close()
	if lease, err := startSource(t, ctx, db, configuration.Input{Mode: settingsdomain.SourceAPI}); !errors.Is(err, settingsdomain.ErrSourceConflict) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("implicit mode switch", err)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.smtp_settings`)
	if lease, err := startSource(t, ctx, db, changed); !errors.Is(err, settingsdomain.ErrNotInitialized) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("lost settings reseeded", err)
	}
}

func TestSettingsSourceLegacyAdoptionSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	if lease, err := startSource(t, ctx, db, sourceInput()); !errors.Is(err, settingsdomain.ErrSourceAdoption) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("legacy settings adopted by ENV", err)
	}
	before, err := settingspostgres.New(db).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := startSource(t, ctx, db, configuration.Input{Mode: settingsdomain.SourceAPI})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	after, err := settingspostgres.New(db).Load(ctx)
	if err != nil || before != after {
		t.Fatal("API adoption changed policy", err)
	}
}
