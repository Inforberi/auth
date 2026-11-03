package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type telegramFactorRepoStub struct{ writes int }

func (*telegramFactorRepoStub) ReadTelegramFactor(context.Context, mfaservice.Proof) (*domain.TelegramFactor, error) {
	return &domain.TelegramFactor{}, nil
}

func (r *telegramFactorRepoStub) EnableTelegramFactor(context.Context, mfatelegram.FactorMutation, domain.TelegramBotBinding) error {
	r.writes++
	return nil
}

func (r *telegramFactorRepoStub) DisableTelegramFactor(context.Context, mfatelegram.FactorMutation) error {
	r.writes++
	return nil
}

func TestTelegramFactorAdmissionFailsClosed(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "telegram-factor:test")
	require.NoError(t, err)
	repo, limit := &telegramFactorRepoStub{}, &limitStub{}
	cfg := mfatelegram.TelegramFactorConfig{Bot: domain.TelegramBotBinding{ID: 123456789, PolicyVersion: 1}, UserMutationsPerMinute: 5, ProjectMutationsPerMinute: 500}
	svc, err := mfatelegram.NewTelegramFactors(repo, cipher, limit, cfg)
	require.NoError(t, err)
	proof := mfaservice.Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}
	for _, change := range []func(context.Context, mfaservice.Proof) error{svc.Enable, svc.Disable} {
		require.ErrorIs(t, change(t.Context(), mfaservice.Proof{}), domain.ErrProofRequired)
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
	_, err = mfatelegram.NewTelegramFactors(repo, cipher, limit, cfg)
	require.ErrorIs(t, err, domain.ErrUnavailable)
}
