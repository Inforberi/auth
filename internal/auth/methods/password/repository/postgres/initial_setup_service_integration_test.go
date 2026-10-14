package postgres

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
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
	s, err := accountservice.NewSetup(accountpostgres.New(db), mfaTestLimit{}, cipher, factor, mail, hash, mfatotp.Authenticator{}, accountservice.SetupConfig{Enabled: true, Secret: operator}, "Auth")
	if err != nil {
		t.Fatal(err)
	}
	started, err := s.Start(ctx, accountservice.SetupStartInput{OperatorSecret: operator, Email: "first-admin@example.test", Password: "Validpassword1", IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&count); err != nil || count != 0 {
		t.Fatal("user exists before proof", err)
	}
	completed, err := s.Complete(ctx, accountservice.SetupCompleteInput{OperatorSecret: operator, Token: started.Token, EmailCode: mail.code, TOTP: mfaCode(t, db, ctx, started.Secret, 0), IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := New(db).FindByEmail(ctx, "first-admin@example.test")
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
	login, err := mfaservice.NewLogin(mfapostgres.New(db), factor, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := login.Start(ctx, mfaservice.PrimaryProof{UserID: credential.UserID, AuthVersion: credential.AuthVersion, Method: "password", Reference: credential.PasswordHash, VerifiedAt: time.Now().UTC()}, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	session, err := login.Complete(ctx, mfaservice.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: completed.RecoveryCodes[0], Recovery: true, UserAgent: "setup test", IP: "192.0.2.1"})
	if err != nil || session.UserID != credential.UserID || session.MFAVerified.IsZero() {
		t.Fatal("normal MFA login incompatible", err)
	}
	if _, err := mfaService(t, db).Verify(ctx, mfaservice.VerifyInput{UserID: credential.UserID, AuthVersion: credential.AuthVersion, Code: completed.RecoveryCodes[0], Recovery: true}); err == nil {
		t.Fatal("recovery code replay")
	}
}
