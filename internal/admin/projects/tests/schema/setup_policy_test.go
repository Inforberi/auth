package platform_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestPlatformSetupMFAPolicy(t *testing.T) {
	for _, mode := range []settingsdomain.MFAMode{settingsdomain.MFAOptional, settingsdomain.MFARequired} {
		t.Run(string(mode), func(t *testing.T) {
			db, ctx := catalogFixture(t)
			operatorMigration(t, db, ctx, "auth/000001_init.up.sql")
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				defer stop()
				operatorMigration(t, db, cleanup, "auth/000001_init.down.sql")
			})
			operatorMigration(t, db, ctx, "admin/000002_operators.up.sql")
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				defer stop()
				operatorMigration(t, db, cleanup, "admin/000002_operators.down.sql")
			})
			var realm domain.RealmID
			require.NoError(t, db.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm`).Scan(&realm))
			repo, err := operators.New(db, realm)
			require.NoError(t, err)
			key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
			cipher, err := secretbox.NewScoped(key, "initial-setup:v1")
			require.NoError(t, err)
			factor, err := secretbox.NewScoped(key, "mfa:v1")
			require.NoError(t, err)
			hash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1)
			secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
			mail := &operatorMail{}
			setup, err := accountservice.NewSetup(repo, operatorLimit{}, cipher, factor, mail, hash, mfatotp.Authenticator{}, accountservice.SetupConfig{Enabled: true, Secret: secret}, "Platform")
			require.NoError(t, err)
			started, err := setup.Start(ctx, accountservice.SetupStartInput{OperatorSecret: secret, Email: "owner@example.test", Password: "Validpassword1", IP: "192.0.2.1", MFAMode: mode})
			require.NoError(t, err)
			input := accountservice.SetupCompleteInput{OperatorSecret: secret, Token: started.Token, EmailCode: mail.code, IP: "192.0.2.1"}
			if mode != settingsdomain.MFAOptional {
				var now time.Time
				require.NoError(t, db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now))
				input.TOTP, err = totp.GenerateCode(started.Secret, now)
				require.NoError(t, err)
			}
			// Policy and both owners must roll back when the final platform audit fails.
			_, err = db.Exec(ctx, `ALTER TABLE platform.operator_audit ADD CONSTRAINT reject_setup_policy CHECK(false)`)
			require.NoError(t, err)
			_, err = setup.Complete(ctx, input)
			require.ErrorIs(t, err, accountdomain.ErrDependencyUnavailable)
			var clean bool
			require.NoError(t, db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.users)
				AND NOT EXISTS(SELECT 1 FROM auth.mfa_settings_audit)
				AND EXISTS(SELECT 1 FROM auth.mfa_settings WHERE mode='administrators' AND version=1 AND session_revision=1)
				AND EXISTS(SELECT 1 FROM platform.operator_realm WHERE initialized_at IS NULL)`).Scan(&clean))
			require.True(t, clean)
			_, err = db.Exec(ctx, `ALTER TABLE platform.operator_audit DROP CONSTRAINT reject_setup_policy`)
			require.NoError(t, err)
			result, err := setup.Complete(ctx, input)
			require.NoError(t, err)
			var stored settingsdomain.MFAMode
			var owner accountdomain.UserID
			require.NoError(t, db.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings WHERE singleton`).Scan(&stored))
			require.Equal(t, mode, stored)
			require.NoError(t, db.QueryRow(ctx, `SELECT first_operator_id::text FROM platform.operator_realm WHERE initialized_at IS NOT NULL`).Scan(&owner))
			require.ErrorIs(t, repo.CheckSetupOpen(ctx), accountdomain.ErrSetupClosed)
			_, err = setup.Complete(ctx, input)
			require.ErrorIs(t, err, accountdomain.ErrSetupClosed)
			var audits int
			require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_settings_audit WHERE actor_id=$1`, owner).Scan(&audits))
			require.Equal(t, 1, audits)
			if mode == settingsdomain.MFARequired {
				require.Len(t, result.RecoveryCodes, 10)
				return
			}
			require.Empty(t, started.Secret)
			require.Empty(t, result.RecoveryCodes)
			require.NoError(t, db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.mfa_totp)
				AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_codes) AND NOT EXISTS(SELECT 1 FROM auth.mfa_audit)`).Scan(&clean))
			require.True(t, clean)
			var passwordHash string
			require.NoError(t, db.QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id=$1`, owner).Scan(&passwordHash))
			now := time.Now().UTC()
			actor := domain.Principal{UserID: owner, TokenHash: strings.Repeat("c", 64)}
			proof := mfaservice.PrimaryProof{UserID: owner, AuthVersion: 1, Method: "password", Reference: passwordHash, VerifiedAt: now, Administrative: true}
			_, err = sessionpostgres.New(db).CreateSession(ctx, sessionservice.CreateSessionParams{PrimaryProof: &proof, UserID: owner, AuthVersion: 1, TokenHash: actor.TokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour)})
			require.NoError(t, err)
			policy, err := repo.ReadMFAPolicy(ctx, actor)
			require.NoError(t, err)
			_, err = repo.UpdateMFAPolicy(ctx, actor, settingsservice.MFAChange{ExpectedVersion: policy.Version, Policy: policy.Policy}, true)
			require.NoError(t, err, "optional owner must manage settings without hidden enrollment")
		})
	}
}
