package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type rejectGuessBudget struct{ counts []int }

func (l *rejectGuessBudget) Allow(_ context.Context, _ string, count int, _ time.Duration) (bool, error) {
	l.counts = append(l.counts, count)
	return count != 5, nil
}

func (l *rejectGuessBudget) AllowAll(_ context.Context, budgets []Budget) (bool, error) {
	allowed := true
	for _, budget := range budgets {
		l.counts = append(l.counts, budget.Count)
		allowed = allowed && budget.Count != 5
	}
	return allowed, nil
}

func TestStepUpGuessBudgetIndependentOfOperations(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	limits := &rejectGuessBudget{}
	svc, err := NewConfigured(&repositoryStub{}, cipher, totp.Authenticator{}, limits, tokengenerate.New(), Config{Enabled: true, Issuer: "Auth", ChallengeTTL: 5 * time.Minute, UserLimitPerMinute: 500, IPLimitPerMinute: 1000, GlobalLimitPerMinute: 10000})
	if err != nil {
		t.Fatal(err)
	}
	input := StepUpInput{Proof: Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}, Code: "123456"}
	if result, err := svc.StepUp(context.Background(), input); result != nil || !errors.Is(err, domain.ErrLimited) || len(limits.counts) != 3 || limits.counts[2] != 5 {
		t.Fatal("operational budget increased TOTP guessing", err, limits.counts)
	}
}
