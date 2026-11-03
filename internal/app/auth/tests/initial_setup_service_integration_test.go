package auth_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountsetup "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type setupSQLMail struct{ code string }

func (m *setupSQLMail) SendContext(_ context.Context, _, _, body string) error {
	_, after, _ := strings.Cut(body, "<strong>")
	m.code, _, _ = strings.Cut(after, "</strong>")
	return nil
}

func TestInitialSetupServiceSQL(t *testing.T) {
	for _, mode := range []settingsdomain.MFAMode{settingsdomain.MFAOptional, settingsdomain.MFAAdministrators, settingsdomain.MFARequired} {
		t.Run(string(mode), func(t *testing.T) { initialSetupServiceSQL(t, mode) })
	}
}

func initialSetupServiceSQL(t *testing.T, mode settingsdomain.MFAMode) {
	t.Helper()
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cipher, err := secretbox.NewScoped(key, "initial-setup:v1")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := secretbox.NewScoped(key, "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	hash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1)
	operator := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	mail := &setupSQLMail{}
	s, err := accountsetup.NewSetup(accountpostgres.New(db), mfaTestLimit{}, cipher, factor, mail, hash, totp.Authenticator{}, accountsetup.SetupConfig{Enabled: true, Secret: operator}, "Auth")
	if err != nil {
		t.Fatal(err)
	}
	started, err := s.Start(ctx, accountsetup.SetupStartInput{OperatorSecret: operator, Email: "first-admin@example.test", Password: "Validpassword1", IP: "192.0.2.1", MFAMode: mode})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&count); err != nil || count != 0 {
		t.Fatal("user exists before proof", err)
	}
	var code string
	if mode != settingsdomain.MFAOptional {
		code = mfaCode(t, db, ctx, started.Secret, 0)
	}
	completed, err := s.Complete(ctx, accountsetup.SetupCompleteInput{OperatorSecret: operator, Token: started.Token, EmailCode: mail.code, TOTP: code, IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := passwordpostgres.New(db).FindByEmail(ctx, "first-admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := hash.Compare(ctx, "Validpassword1", credential.PasswordHash); err != nil {
		t.Fatal("wrong password hash", err)
	}
	var sessions int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("setup issued a session", err)
	}
	var stored settingsdomain.MFAMode
	if err := db.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings WHERE singleton`).Scan(&stored); err != nil || stored != mode {
		t.Fatal("setup lost policy", err, stored)
	}
	if mode == settingsdomain.MFAOptional {
		if len(completed.RecoveryCodes) != 0 || started.Secret != "" {
			t.Fatal("optional setup created a factor")
		}
		var empty bool
		if err := db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.mfa_totp)
			AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_codes) AND NOT EXISTS(SELECT 1 FROM auth.mfa_audit)`).Scan(&empty); err != nil || !empty {
			t.Fatal("optional setup stored factor data", err)
		}
		now := time.Now().UTC()
		proof := mfaservice.PrimaryProof{UserID: credential.UserID, AuthVersion: credential.AuthVersion, Method: "password", Reference: credential.PasswordHash, VerifiedAt: now, Administrative: true}
		repo := sessionpostgres.New(db)
		_, err := repo.CreateSession(ctx, sessionservice.CreateSessionParams{
			UserID: credential.UserID, AuthVersion: credential.AuthVersion, PrimaryProof: &proof,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour), TokenHash: strings.Repeat("e", 64), IPAddress: "192.0.2.1",
		})
		if err != nil {
			t.Fatal("optional owner cannot log in with permanent password", err)
		}
		if _, err := repo.FindSession(ctx, strings.Repeat("e", 64)); err != nil {
			t.Fatal("optional owner session unusable", err)
		}
		return
	}
	login, err := mfalogin.NewLogin(mfapostgres.New(db), factor, totp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := login.Start(ctx, mfaservice.PrimaryProof{UserID: credential.UserID, AuthVersion: credential.AuthVersion, Method: "password", Reference: credential.PasswordHash, VerifiedAt: time.Now().UTC()}, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	session, err := login.Complete(ctx, mfalogin.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: completed.RecoveryCodes[0], Recovery: true, UserAgent: "setup test", IP: "192.0.2.1"})
	if err != nil || session.UserID != credential.UserID || session.MFAVerified.IsZero() {
		t.Fatal("normal MFA login incompatible", err)
	}
	if _, err := mfaService(t, db).Verify(ctx, mfamanagement.VerifyInput{UserID: credential.UserID, AuthVersion: credential.AuthVersion, Code: completed.RecoveryCodes[0], Recovery: true}); err == nil {
		t.Fatal("recovery code replay")
	}
}
