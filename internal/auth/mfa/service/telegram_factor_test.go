package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type telegramFactorRepoStub struct{ writes int }

func (*telegramFactorRepoStub) ReadTelegramFactor(context.Context, Proof) (*domain.TelegramFactor, error) {
	return &domain.TelegramFactor{}, nil
}

func (r *telegramFactorRepoStub) EnableTelegramFactor(context.Context, Proof, domain.TelegramBotBinding) error {
	r.writes++
	return nil
}

func (r *telegramFactorRepoStub) DisableTelegramFactor(context.Context, Proof) error {
	r.writes++
	return nil
}

func TestTelegramFactorAdmissionFailsClosed(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "telegram-factor:test")
	require.NoError(t, err)
	repo, limit := &telegramFactorRepoStub{}, &limitStub{}
	cfg := TelegramFactorConfig{Bot: domain.TelegramBotBinding{ID: 123456789, PolicyVersion: 1}, UserMutationsPerMinute: 5, ProjectMutationsPerMinute: 500}
	svc, err := NewTelegramFactors(repo, cipher, limit, cfg)
	require.NoError(t, err)
	proof := Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}
	for _, change := range []func(context.Context, Proof) error{svc.Enable, svc.Disable} {
		require.ErrorIs(t, change(t.Context(), Proof{}), domain.ErrProofRequired)
		require.ErrorIs(t, change(t.Context(), proof), domain.ErrLimited)
		limit.err = errors.New("Redis unavailable")
		require.ErrorIs(t, change(t.Context(), proof), domain.ErrUnavailable)
		limit.err = nil
	}
	require.Zero(t, repo.writes)
	limit.allowed = true
	require.NoError(t, svc.Enable(t.Context(), proof))
	require.NoError(t, svc.Disable(t.Context(), proof))
	require.Equal(t, 2, repo.writes)
	cfg.Bot.PolicyVersion = 0
	_, err = NewTelegramFactors(repo, cipher, limit, cfg)
	require.ErrorIs(t, err, domain.ErrUnavailable)
}
