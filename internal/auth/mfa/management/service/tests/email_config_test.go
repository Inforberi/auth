package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type emailConfigLimiter struct{ budgets []mfaservice.Budget }

func (l *emailConfigLimiter) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}

func (l *emailConfigLimiter) AllowAll(_ context.Context, budgets []mfaservice.Budget) (bool, error) {
	l.budgets = append([]mfaservice.Budget(nil), budgets...)
	return true, nil
}

func TestEmailFactorConfiguredBudgets(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "mfa:v1")
	require.NoError(t, err)
	limit := &emailConfigLimiter{}
	repo := &emailFactorRepoStub{}
	_, err = mfamanagement.NewConfiguredEmailFactors(repo, cipher, limit, mfamanagement.EmailFactorConfig{})
	require.Error(t, err)
	service, err := mfamanagement.NewConfiguredEmailFactors(repo, cipher, limit, mfamanagement.EmailFactorConfig{UserMutationsPerMinute: 7, ProjectMutationsPerMinute: 900})
	require.NoError(t, err)
	require.NoError(t, service.Enable(t.Context(), mfaservice.Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}))
	require.Len(t, limit.budgets, 2)
	require.Equal(t, 7, limit.budgets[0].Count)
	require.Equal(t, 900, limit.budgets[1].Count)
}
