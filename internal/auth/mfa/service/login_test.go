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
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type loginRepoStub struct {
	err       error
	calls     int
	proof     PrimaryProof
	digest    string
	binding   string
	completed LoginCompletion
	recovery  string
}

func (r *loginRepoStub) FindLoginOwner(context.Context, string, string) (accountdomain.UserID, error) {
	return r.proof.UserID, r.err
}

func (r *loginRepoStub) SaveLoginChallenge(_ context.Context, proof PrimaryProof, digest, binding string, ttl time.Duration) (*LoginChallengeState, error) {
	r.calls++
	r.proof, r.digest, r.binding = proof, digest, binding
	return &LoginChallengeState{ExpiresAt: time.Now().Add(ttl)}, r.err
}

func (r *loginRepoStub) SaveLoginEnrollment(context.Context, LoginEnrollmentParams) (time.Time, error) {
	return time.Time{}, errors.New("unexpected enrollment call")
}

func (r *loginRepoStub) ConfirmLoginEnrollment(context.Context, LoginEnrollmentParams, Check, []string) error {
	return domain.ErrUnavailable
}

func (r *loginRepoStub) CompleteLogin(_ context.Context, input LoginCompletion, factor LoginFactor) (*LoginCommit, error) {
	r.calls++
	r.completed = input
	_, r.recovery = factor(r.proof.UserID)
	if r.err != nil {
		return nil, r.err
	}
	return &LoginCommit{UserID: r.proof.UserID, ExpiresAt: time.Now().Add(time.Hour), MFAVerified: time.Now()}, nil
}

func loginTestConfig() LoginConfig {
	return LoginConfig{
		ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
		UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
	}
}

func TestAdministrativePrimaryIntent(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := loginTestConfig()
	cfg.AllowPrimary = func(string, string) bool { return false }
	repo := &loginRepoStub{}
	svc, err := NewLogin(repo, cipher, totp.Authenticator{}, &limitStub{allowed: true}, tokengenerate.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	proof := PrimaryProof{UserID: "11111111-1111-4111-8111-111111111111", AuthVersion: 1, Method: "password", Reference: "hash", VerifiedAt: time.Now()}
	if _, err := svc.Start(context.Background(), proof, ""); !errors.Is(err, domain.ErrProofRequired) || repo.calls != 0 {
		t.Fatal("public method bypass", err)
	}
	proof.Administrative = true
	if _, err := svc.Start(context.Background(), proof, ""); err != nil || !repo.proof.Administrative {
		t.Fatal("private intent lost", err)
	}
	proof.Method, proof.Reference = "emailotp", "22222222-2222-4222-8222-222222222222"
	if _, err := svc.Start(context.Background(), proof, ""); !errors.Is(err, domain.ErrProofRequired) || repo.calls != 1 {
		t.Fatal("non-password administrative proof", err)
	}
}

func TestLoginBoundaries(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo, limit := &loginRepoStub{}, &limitStub{allowed: true}
	svc, err := NewLogin(repo, cipher, totp.Authenticator{}, limit, tokengenerate.New(), loginTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	proof := PrimaryProof{
		UserID: accountdomain.UserID("11111111-1111-4111-8111-111111111111"), AuthVersion: 2,
		Method: "password", Reference: "verified-hash", VerifiedAt: time.Now(),
	}
	challenge, err := svc.Start(context.Background(), proof, "192.0.2.1")
	if err != nil || !validLoginToken(challenge.Token) || !validLoginToken(challenge.Binding) || challenge.Token == challenge.Binding {
		t.Fatal("invalid challenge", err)
	}
	if repo.digest != cipher.Digest("login:"+challenge.Token) || repo.binding != cipher.Digest("browser:"+challenge.Binding) || repo.proof != proof {
		t.Fatal("incorrect proof/binding")
	}
	encoded, err := json.Marshal(challenge)
	if err != nil || strings.Contains(string(encoded), challenge.Token) || strings.Contains(string(encoded), challenge.Binding) {
		t.Fatal("challenge secret serialization", err)
	}
	input := CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: strings.Repeat("a", 32), Recovery: true, IP: "192.0.2.1"}
	result, err := svc.Complete(context.Background(), input)
	if len(limit.keys) < 4 || limit.keys[3] != "login:complete:subject:"+cipher.Digest(input.Token+":"+input.Binding) {
		t.Fatal("browser binding missing from admission budget")
	}
	if limit.keys[0] != limit.keys[6] || limit.keys[1] != limit.keys[4] || limit.keys[2] != limit.keys[5] {
		t.Fatal("start/completion operation budgets are not shared")
	}
	if limit.counts[len(limit.counts)-1] != 5 || limit.keys[len(limit.keys)-1] != cipher.Digest("login:factor-user:"+string(proof.UserID)) {
		t.Fatal("account guessing bound missing")
	}
	if err != nil || result.UserID != proof.UserID || len(repo.completed.SessionHash) != 64 || repo.completed.SessionHash == result.Token ||
		repo.recovery != cipher.Digest("recovery:"+string(proof.UserID)+":"+input.Code) {
		t.Fatal("completion contract", err)
	}
	encoded, err = json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), result.Token) {
		t.Fatal("session secret serialization", err)
	}
	repo.err = errors.New("commit failed")
	if result, err := svc.Complete(context.Background(), input); err == nil || result != nil {
		t.Fatal("session returned before commit")
	}
	before := repo.calls
	limit.err = errors.New("Redis down")
	if _, err := svc.Complete(context.Background(), input); !errors.Is(err, domain.ErrUnavailable) || repo.calls != before {
		t.Fatal("Redis fail-open", err)
	}
	limit.err, limit.allowed = nil, false
	if _, err := svc.Start(context.Background(), proof, "192.0.2.1"); !errors.Is(err, domain.ErrLimited) || repo.calls != before {
		t.Fatal("admission bypass", err)
	}
	limit.allowed = true
	calls := limit.calls
	input.Binding = strings.Repeat("a", 10000)
	if _, err := svc.Complete(context.Background(), input); !errors.Is(err, domain.ErrInvalidCode) || limit.calls != calls {
		t.Fatal("invalid input reached dependencies", err)
	}
}

func TestLoginPrimaryAndConfig(t *testing.T) {
	p := PrimaryProof{UserID: "11111111-1111-4111-8111-111111111111", AuthVersion: 1, VerifiedAt: time.Now()}
	for _, method := range []string{"password", "oidc", "emailotp"} {
		p.Method, p.Issuer, p.Reference = method, "", "hash"
		if method == "oidc" {
			p.Issuer = "https://accounts.example.com"
		}
		if method == "emailotp" {
			p.Reference = string(p.UserID)
		}
		if !ValidPrimary(p) {
			t.Fatal("valid primary rejected", method)
		}
	}
	p.Method = "unknown"
	if ValidPrimary(p) {
		t.Fatal("unknown primary accepted")
	}
	if _, err := NewLogin(nil, nil, nil, nil, nil, loginTestConfig()); err == nil {
		t.Fatal("nil dependencies accepted")
	}
}
