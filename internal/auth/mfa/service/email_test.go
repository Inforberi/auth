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

type emailFactorRepoStub struct{ writes int }

func (r *emailFactorRepoStub) ReadEmailFactor(context.Context, Proof) (*domain.EmailFactor, error) {
	return &domain.EmailFactor{}, nil
}

func (r *emailFactorRepoStub) EnableEmailFactor(context.Context, Proof) error {
	r.writes++
	return nil
}

func (r *emailFactorRepoStub) DisableEmailFactor(context.Context, Proof) error {
	r.writes++
	return nil
}

func TestEmailFactorAdmissionFailsClosed(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "mfa:v1")
	require.NoError(t, err)
	repo := &emailFactorRepoStub{}
	limit := &limitStub{}
	svc, err := NewEmailFactors(repo, cipher, limit)
	require.NoError(t, err)
	proof := Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}
	for _, change := range []func(context.Context, Proof) error{svc.Enable, svc.Disable} {
		require.ErrorIs(t, change(context.Background(), Proof{}), domain.ErrProofRequired)
		require.ErrorIs(t, change(context.Background(), proof), domain.ErrLimited)
		limit.err = errors.New("Redis unavailable")
		require.ErrorIs(t, change(context.Background(), proof), domain.ErrUnavailable)
		limit.err = nil
	}
	require.Zero(t, repo.writes)
	limit.allowed = true
	require.NoError(t, svc.Enable(context.Background(), proof))
	require.NoError(t, svc.Disable(context.Background(), proof))
	require.Equal(t, 2, repo.writes)
}
