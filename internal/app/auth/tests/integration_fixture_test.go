package auth_test

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func schemaFixture(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	return schemaFixtureDSN(t, os.Getenv("AUTH_SCHEMA_TEST_DATABASE_URL"), 60*time.Second)
}

func schemaFixtureDSN(t *testing.T, dsn string, timeout time.Duration) (*pgxpool.Pool, context.Context) {
	t.Helper()
	if dsn == "" {
		t.Skip("explicit disposable schema database not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/auth_schema_test" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.User == nil || u.User.Username() != "auth_schema_test" {
		t.Fatal("schema check requires the dedicated localhost auth_schema_test fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 10
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var present bool
	if err := db.QueryRow(ctx, "SELECT to_regnamespace('auth') IS NOT NULL").Scan(&present); err != nil || present {
		t.Fatal("fixture must be a fresh database without auth schema")
	}
	return db, ctx
}

func migrateFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, direction string) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "migrations", "auth", "000001_init."+direction+".sql")
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sessionSQL, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000004_browser_session_policy."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	linkSQL, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000005_link_lifetime_policy."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	credentialSQL, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000006_credential_lifetime_policy."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	budgetSQL, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000007_login_budget_policy."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	frontendSQL, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000008_frontend_policy."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	operationsSQL, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000009_operation_budgets_policy."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	switch direction {
	case "down":
		// This fixture owns the whole database. Release ENV ownership only for teardown.
		otpDown, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000003_email_otp_policy.down.sql"))
		if err != nil {
			t.Fatal(err)
		}
		down, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000002_settings_source.down.sql"))
		if err != nil {
			t.Fatal(err)
		}
		sessionSQL = append(sessionSQL, otpDown...)
		sessionSQL = append(sessionSQL, "UPDATE auth.settings_source SET initialized=false;\n"...)
		sessionSQL = append(sessionSQL, down...)
		sessionSQL = append(sessionSQL, sql...)
		linkSQL = append(linkSQL, sessionSQL...)
		credentialSQL = append(credentialSQL, linkSQL...)
		frontendSQL = append(frontendSQL, budgetSQL...)
		frontendSQL = append(frontendSQL, credentialSQL...)
		operationsSQL = append(operationsSQL, frontendSQL...)
		sql = operationsSQL
	case "up":
		extra, readErr := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", "auth", "000002_settings_source.up.sql"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		otpUp, err := os.ReadFile(filepath.Join(filepath.Dir(path), "000003_email_otp_policy.up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		sql = append(append(append(sql, extra...), otpUp...), sessionSQL...)
		sql = append(sql, linkSQL...)
		sql = append(sql, credentialSQL...)
		sql = append(sql, budgetSQL...)
		sql = append(sql, frontendSQL...)
		sql = append(sql, operationsSQL...)
	}
	if _, err := db.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("%s migration: %v", direction, err)
	}
	if direction == "up" {
		_, err := settingspostgres.New(db).Initialize(ctx, settingsdomain.Policy{
			Methods:      settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true},
			Registration: settingsdomain.PublicRegistration{Enabled: true, Google: true, Telegram: true}, PasswordEmailVerification: settingsdomain.VerificationOptional,
			TokenIssuance: settingsdomain.TokenIssuance{SessionExchange: true, Native: true},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
