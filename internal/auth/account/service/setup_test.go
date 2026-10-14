package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type setupFixture struct {
	payload                                 []byte
	operator, request, email, body          string
	checks, saves, completes, hashes, mails int
	closed                                  bool
	limitOK                                 bool
	limitErr, mailErr, errorCheck           error
	account                                 *domain.SetupAccount
}

func (f *setupFixture) CheckSetupOpen(context.Context) error {
	f.checks++
	if f.closed {
		return domain.ErrSetupClosed
	}
	return nil
}

func (f *setupFixture) SaveSetup(_ context.Context, operator, request string, payload []byte) (time.Time, error) {
	f.saves++
	f.operator, f.request, f.payload = operator, request, payload
	return time.Now().Add(10 * time.Minute), nil
}

func (f *setupFixture) CompleteSetup(_ context.Context, operator, request string, check SetupCheck) error {
	f.completes++
	if operator != f.operator || request != f.request {
		return domain.ErrSetupInvalid
	}
	f.account, f.errorCheck = check(f.payload, time.Now())
	if f.errorCheck == nil {
		f.closed = true
	}
	return f.errorCheck
}

func (f *setupFixture) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return f.limitOK, f.limitErr
}

func (f *setupFixture) GenerateHash(context.Context, []byte) (string, error) {
	f.hashes++
	return "synthetic-hash", nil
}

func (f *setupFixture) SendContext(_ context.Context, to, _, body string) error {
	f.mails++
	f.email, f.body = to, body
	return f.mailErr
}

func (*setupFixture) Generate(string, string) (string, string, error) {
	return "synthetic-totp-secret", "otpauth://synthetic", nil
}

func (*setupFixture) Match(_, code string, _ time.Time, _ int64) (int64, error) {
	if code != "123456" {
		return 0, mfadomain.ErrInvalidCode
	}
	return time.Now().Unix() / 30, nil
}

func setupServiceFixture(t *testing.T) (*SetupService, *setupFixture, string) {
	t.Helper()
	f := &setupFixture{limitOK: true}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	cipher, err := secretbox.NewScoped(key, "initial-setup:v1")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := secretbox.NewScoped(key, "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	operator := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	s, err := NewSetup(f, f, cipher, factor, f, f, f, SetupConfig{Enabled: true, Secret: operator}, "Auth")
	if err != nil {
		t.Fatal(err)
	}
	return s, f, operator
}

func TestInitialSetupFlow(t *testing.T) {
	s, f, operator := setupServiceFixture(t)
	start, err := s.Start(context.Background(), SetupStartInput{OperatorSecret: operator, Email: " OWNER@example.test ", Password: "Validpass1", IP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if f.email != "owner@example.test" || strings.Contains(string(f.payload), "owner") || strings.Contains(string(f.payload), "synthetic") || start.Token == "" || f.closed {
		t.Fatal("invalid pending setup")
	}
	_, after, _ := strings.Cut(f.body, "<strong>")
	code, _, _ := strings.Cut(after, "</strong>")
	input := SetupCompleteInput{OperatorSecret: operator, Token: start.Token, EmailCode: code, TOTP: "000000", IP: "127.0.0.1"}
	if _, err := s.Complete(context.Background(), input); !errors.Is(err, domain.ErrSetupInvalid) {
		t.Fatal(err)
	}
	input.TOTP = "123456"
	result, err := s.Complete(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RecoveryCodes) != 10 || len(f.account.RecoveryDigests) != 10 || !domain.ValidUserID(f.account.UserID) {
		t.Fatal("missing confirmed account")
	}
	plain, err := s.factorCipher.Open(f.account.Factor)
	if err != nil || string(plain) != string(f.account.UserID)+"\x00synthetic-totp-secret" {
		t.Fatal("wrong factor scope")
	}
	for i, code := range result.RecoveryCodes {
		if f.account.RecoveryDigests[i] != s.factorCipher.Digest("recovery:"+string(f.account.UserID)+":"+code) {
			t.Fatal("wrong recovery scope")
		}
	}
	if _, err := s.Complete(context.Background(), input); !errors.Is(err, domain.ErrSetupClosed) {
		t.Fatal("replay", err)
	}
}

func TestInitialSetupAdmission(t *testing.T) {
	for _, mode := range []string{"operator", "limited", "redis", "closed", "email", "password", "smtp"} {
		t.Run(mode, func(t *testing.T) {
			s, f, operator := setupServiceFixture(t)
			input := SetupStartInput{OperatorSecret: operator, Email: "owner@example.test", Password: "Validpass1", IP: "127.0.0.1"}
			want := domain.ErrSetupUnauthorized
			switch mode {
			case "operator":
				input.OperatorSecret = strings.Repeat("a", 43)
			case "limited":
				f.limitOK = false
				want = domain.ErrVerificationLimited
			case "redis":
				f.limitErr = errors.New("offline")
				want = domain.ErrDependencyUnavailable
			case "closed":
				f.closed = true
				want = domain.ErrSetupClosed
			case "email":
				input.Email = "not-email"
				want = domain.ErrEmailInvalid
			case "password":
				input.Password = "short"
				want = domain.ErrSetupPasswordPolicy
			case "smtp":
				f.mailErr = errors.New("offline")
				want = domain.ErrDependencyUnavailable
			}
			_, err := s.Start(context.Background(), input)
			if err == nil || (want != nil && !errors.Is(err, want)) {
				t.Fatal(err)
			}
			if mode != "smtp" && (f.saves != 0 || f.mails != 0 || f.hashes != 0) {
				t.Fatal("side effect before admission/validation")
			}
			if (mode == "operator" || mode == "limited" || mode == "redis") && f.checks != 0 {
				t.Fatal("SQL before operator proof")
			}
		})
	}
}

func TestInitialSetupConfig(t *testing.T) {
	_, _, secret := setupServiceFixture(t)
	for _, value := range []string{"", "change-me", strings.Repeat("A", 43), secret + "=", secret} {
		err := (SetupConfig{Enabled: true, Secret: value}).Validate()
		if (value == secret) != (err == nil) {
			t.Fatal("config acceptance", value == secret, err)
		}
	}
	if err := (SetupConfig{}).Validate(); err != nil {
		t.Fatal(err)
	}
}
