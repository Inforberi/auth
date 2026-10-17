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

func TestRecoveryCompletionContract(t *testing.T) {
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
	input := CompleteRecoveryInput{RequestID: "22222222-2222-4222-8222-222222222222", Token: token, Binding: binding, Code: "123456", IP: "192.0.2.1"}
	result, err := svc.Complete(context.Background(), input)
	if err != nil || len(result.Codes) != domain.RecoveryCodeCount || repo.calls != 1 {
		t.Fatal(result, err)
	}
	if repo.completion.UserID != user || repo.completion.Digest != cipher.Digest("login:"+token) || repo.completion.BindingHash != cipher.Digest("browser:"+binding) || repo.completion.RequestID != input.RequestID {
		t.Fatal("completion binding")
	}
	for i, code := range result.Codes {
		if !domain.ValidRecoveryCode(code) || repo.completion.RecoveryDigests[i] != cipher.Digest("recovery:"+string(user)+":"+code) {
			t.Fatal("recovery scope")
		}
	}
	if len(limit.keys) != 5 || limit.keys[3] != cipher.Digest("user:"+string(user)) || limit.keys[4] != cipher.Digest("login:factor-user:"+string(user)) || limit.counts[4] != 5 {
		t.Fatal("shared guessing budget", limit.keys)
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), result.Codes[0]) {
		t.Fatal("codes serialized", err)
	}
	sealed, err := repo.completion.PrepareNotice("owner@example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.Open(sealed)
	if err != nil || !strings.Contains(string(plain), "owner@example.com") || strings.Contains(string(plain), result.Codes[0]) || strings.Contains(string(plain), token) {
		t.Fatal("notice payload", err)
	}
	clear(plain)
	before := repo.calls
	bad := input
	bad.Code = "not-code"
	if _, err := svc.Complete(context.Background(), bad); !errors.Is(err, domain.ErrInvalidCode) || repo.calls != before {
		t.Fatal("invalid input", err)
	}
	repo.err = domain.ErrInvalidCode
	if _, err := svc.Complete(context.Background(), input); !errors.Is(err, domain.ErrInvalidCode) || repo.calls != before {
		t.Fatal("unapproved request", err)
	}
	repo.err = nil
	repo.saveErr = errors.New("commit failed")
	if result, err := svc.Complete(context.Background(), input); err == nil || result != nil {
		t.Fatal("codes exposed on failed commit")
	}
	limit.err = errors.New("Redis unavailable")
	before = repo.calls
	if _, err := svc.Complete(context.Background(), input); !errors.Is(err, domain.ErrUnavailable) || repo.calls != before {
		t.Fatal("Redis failure not closed", err)
	}
}

type recoveryBudget struct{ used map[string]int }

func (l *recoveryBudget) Allow(_ context.Context, key string, count int, _ time.Duration) (bool, error) {
	l.used[key]++
	return l.used[key] <= count, nil
}

func (l *recoveryBudget) AllowAll(_ context.Context, budgets []Budget) (bool, error) {
	for _, budget := range budgets {
		if l.used[budget.Key] >= budget.Count {
			return false, nil
		}
	}
	for _, budget := range budgets {
		l.used[budget.Key]++
	}
	return true, nil
}

func TestRecoveryGuessingBudgetSurvivesReissue(t *testing.T) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	user := accountdomain.UserID("11111111-1111-4111-8111-111111111111")
	repo := &recoveryRepoStub{loginRepoStub: loginRepoStub{proof: PrimaryProof{UserID: user}}, saveErr: domain.ErrInvalidCode}
	budget := &recoveryBudget{used: map[string]int{}}
	cfg := loginTestConfig()
	cfg.UserLimitPerMinute, cfg.IPLimitPerMinute, cfg.GlobalLimitPerMinute = 100, 100, 1000
	recoveryCfg := recoveryTestConfig()
	recoveryCfg.UserLimitPerMinute, recoveryCfg.IPLimitPerMinute, recoveryCfg.GlobalLimitPerMinute = 100, 100, 1000
	svc, err := NewRecovery(repo, cipher, totp.Authenticator{}, budget, recoveryCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := randomLoginToken()
	binding, _ := randomLoginToken()
	input := CompleteRecoveryInput{RequestID: "22222222-2222-4222-8222-222222222222", Token: token, Binding: binding, Code: "123456", IP: "192.0.2.1"}
	for attempt := 1; attempt <= 5; attempt++ {
		if _, err := svc.Complete(context.Background(), input); !errors.Is(err, domain.ErrInvalidCode) {
			t.Fatal("guess", attempt, err)
		}
		if attempt == 3 {
			repo.saveErr = nil
			if _, err := svc.Start(context.Background(), StartRecoveryInput{Token: token, Binding: binding, IP: input.IP}); err != nil {
				t.Fatal(err)
			}
			repo.saveErr = domain.ErrInvalidCode
			input.RequestID = "33333333-3333-4333-8333-333333333333"
		}
	}
	before := repo.calls
	if _, err := svc.Complete(context.Background(), input); !errors.Is(err, domain.ErrLimited) || repo.calls != before {
		t.Fatal("sixth guess reached SQL", err)
	}
	// A fresh normal-login challenge shares the same account budget, not the request UUID.
	loginRepo := &loginRepoStub{proof: PrimaryProof{UserID: user}}
	login, err := NewLogin(loginRepo, cipher, totp.Authenticator{}, budget, tokengenerate.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	freshToken, _ := randomLoginToken()
	if _, err := login.Complete(context.Background(), CompleteLoginInput{Token: freshToken, Binding: binding, Code: "123456", IP: input.IP}); !errors.Is(err, domain.ErrLimited) || loginRepo.calls != 0 {
		t.Fatal("normal login bypassed recovery budget", err)
	}
}
