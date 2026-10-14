package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type recoveryRepoStub struct {
	loginRepoStub
	request    RecoveryRequest
	saveErr    error
	completion RecoveryCompletion
}

func (r *recoveryRepoStub) FindRecoveryOwner(context.Context, string, string, string) (accountdomain.UserID, error) {
	return r.proof.UserID, r.err
}

func (r *recoveryRepoStub) CompleteRecovery(_ context.Context, input RecoveryCompletion) error {
	r.calls++
	r.completion = input
	return r.saveErr
}

func (r *recoveryRepoStub) SaveRecoveryRequest(_ context.Context, input RecoveryRequest) (*RecoveryCandidate, error) {
	r.calls++
	r.request = input
	if r.saveErr != nil {
		return nil, r.saveErr
	}
	return &RecoveryCandidate{RequestID: "22222222-2222-4222-8222-222222222222", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestRecoveryStartBoundaries(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	user := accountdomain.UserID("11111111-1111-4111-8111-111111111111")
	repo := &recoveryRepoStub{loginRepoStub: loginRepoStub{proof: PrimaryProof{UserID: user}}}
	limit := &limitStub{allowed: true}
	svc, err := NewRecovery(repo, cipher, totp.Authenticator{}, limit, recoveryTestConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := randomLoginToken()
	binding, _ := randomLoginToken()
	input := StartRecoveryInput{Token: token, Binding: binding, IP: "192.0.2.1"}
	result, err := svc.Start(context.Background(), input)
	if err != nil || result.Secret == "" || !strings.HasPrefix(result.URI, "otpauth://") {
		t.Fatal(result, err)
	}
	if repo.request.UserID != user || repo.request.Digest != cipher.Digest("login:"+token) || repo.request.BindingHash != cipher.Digest("browser:"+binding) {
		t.Fatal("unbound candidate")
	}
	plain, err := cipher.Open(repo.request.Secret)
	if err != nil || string(plain) != string(user)+"\x00"+result.Secret {
		t.Fatal("owner encryption", err)
	}
	clear(plain)
	if repo.request.AllowPrimary("oidc", "unknown") || !repo.request.AllowPrimary("password", "") {
		t.Fatal("default policy")
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), result.Secret) || strings.Contains(string(encoded), "otpauth") {
		t.Fatal("secret serialized", err)
	}
	if len(limit.keys) != 4 || limit.keys[1] != "login:ip:"+cipher.Digest(input.IP) || limit.keys[2] != "project" || limit.keys[3] != cipher.Digest("user:"+string(user)) {
		t.Fatal("shared budgets", limit.keys)
	}
	before := repo.calls
	bad := input
	bad.Binding = "bad"
	if _, err := svc.Start(context.Background(), bad); !errors.Is(err, domain.ErrInvalidCode) || repo.calls != before {
		t.Fatal("format boundary", err)
	}
	limit.allowed = false
	if _, err := svc.Start(context.Background(), input); !errors.Is(err, domain.ErrLimited) || repo.calls != before {
		t.Fatal("limiter boundary", err)
	}
	limit.allowed = true
	repo.err = domain.ErrInvalidCode
	if _, err := svc.Start(context.Background(), input); !errors.Is(err, domain.ErrInvalidCode) || repo.calls != before {
		t.Fatal("wrong browser/owner", err)
	}
	repo.err = nil
	repo.saveErr = errors.New("audit failed")
	if result, err := svc.Start(context.Background(), input); err == nil || result != nil {
		t.Fatal("candidate exposed without commit")
	}
}

func recoveryTestConfig() Config {
	return Config{Enabled: true, RecoveryEnabled: true, Issuer: "Auth", ChallengeTTL: 5 * time.Minute, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500}
}

func TestDisabledRecoveryStopsBeforeDependencies(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, mfaEnabled := range []bool{false, true} {
		cfg := recoveryTestConfig()
		cfg.Enabled, cfg.RecoveryEnabled = mfaEnabled, false
		repo, limit := &recoveryRepoStub{}, &limitStub{allowed: true}
		svc, err := NewRecovery(repo, cipher, totp.Authenticator{}, limit, cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Start(context.Background(), StartRecoveryInput{}); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatal("disabled start", err)
		}
		if _, err := svc.Complete(context.Background(), CompleteRecoveryInput{}); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatal("disabled complete", err)
		}
		if repo.calls != 0 || limit.calls != 0 {
			t.Fatal("disabled recovery touched dependencies")
		}
	}
}
