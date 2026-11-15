package auth_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	settingsapp "github.com/Inforberi/financial-intelligence/internal/app/auth/settings"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/registration"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestProjectLinkLifetimeUsesStoredPolicy(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })

	baseline := settingsdomain.LinkLifetimePolicy{VerificationSeconds: 1800, ResetSeconds: 1800}
	configured := settingsdomain.LinkLifetimePolicy{VerificationSeconds: 600, ResetSeconds: 900}
	store := settingspostgres.New(db).LinkLifetimePolicy()
	require.NoError(t, pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		got, err := settingspostgres.ProjectLinkLifetime(ctx, tx, baseline, 60)
		if err != nil {
			return err
		}
		require.Equal(t, baseline, got)
		_, err = store.ApplyProject(ctx, tx, "23400000-0000-4000-8000-000000000001", 1, baseline, configured)
		return err
	}))
	got, err := settingspostgres.ProjectLinkLifetime(ctx, db, baseline, 60)
	require.NoError(t, err)
	require.Equal(t, configured, got)
}

func TestVerificationLinkLifetime(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })

	cfg := &config.Config{}
	cfg.Account.URL = "https://example.com/verify"
	cfg.Account.TTL = 30 * time.Minute
	cfg.Account.ResendInterval = time.Minute
	cfg.Password.ResetTokenTTL = time.Hour
	_, err := settingsapp.AssembleLinkLifetimePolicy(ctx, settingspostgres.New(db), cfg, zap.NewNop())
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "email-verification:v1")
	require.NoError(t, err)
	accounts := accountpostgres.New(db)
	verification := accountemail.NewVerification(accounts, verificationLimits{}, cipher, &verificationMail{}, cfg.Account)
	passwords := registration.Assemble(db, verification, accounts, settingsapp.RegistrationLinkTTL(cfg))
	user, err := passwords.CreateUser(ctx, "expiry@example.com", "hash")
	require.NoError(t, err)

	expiry := func() time.Time {
		t.Helper()
		var value time.Time
		require.NoError(t, db.QueryRow(ctx, `SELECT v.expires_at FROM auth.email_verifications v
			JOIN auth.user_emails e ON e.id=v.email_id WHERE e.user_id=$1`, user).Scan(&value))
		return value
	}
	issued := expiry()
	require.WithinDuration(t, time.Now().Add(30*time.Minute), issued, 5*time.Second)
	accessExec(t, db, ctx, `UPDATE auth.link_lifetime_policy SET policy='{"verificationSeconds":600,"resetSeconds":900}' WHERE singleton`)
	require.Equal(t, issued, expiry())
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET verification_sent_at=now()-interval '2 minutes' WHERE user_id=$1`, user)
	require.NoError(t, verification.Resend(ctx, "expiry@example.com", "ip"))
	require.WithinDuration(t, time.Now().Add(10*time.Minute), expiry(), 5*time.Second)
}
