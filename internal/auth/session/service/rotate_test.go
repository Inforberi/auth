package service

import (
	"context"
	"errors"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type rotationRepoStub struct {
	err   error
	calls int
}

func (r *rotationRepoStub) RotateSession(_ context.Context, user accountdomain.UserID, oldHash, newHash string) (time.Time, error) {
	r.calls++
	if user != "owner" || oldHash != "old-hash" || newHash != "new-hash" {
		panic("unexpected rotation input")
	}
	return now.Add(time.Minute), r.err
}

func TestRotateSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"success", nil},
		{"invalid caller", domain.ErrSessionNotFound},
		{"dependency failure", errors.New("SQL unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, token := &rotationRepoStub{err: tc.err}, &mockTokenHash{}
			token.On("GenerateToken").Return("new-raw", nil)
			token.On("Hash", "new-raw").Return("new-hash")
			result, err := NewRotation(repo, token).Rotate(t.Context(), "owner", "old-hash")
			if !errors.Is(err, tc.err) || repo.calls != 1 {
				t.Fatal(result, err, repo.calls)
			}
			if tc.err == nil {
				if result.RawToken != "new-raw" || !result.ExpiresAt.Equal(now.Add(time.Minute)) {
					t.Fatal(result)
				}
			} else if result != nil {
				t.Fatal("failed rotation exposed token")
			}
			token.AssertExpectations(t)
		})
	}
}

func TestRotationGenerationFailureDoesNotMutate(t *testing.T) {
	repo, token := &rotationRepoStub{}, &mockTokenHash{}
	token.On("GenerateToken").Return("", errGenerateToken)
	result, err := NewRotation(repo, token).Rotate(t.Context(), "owner", "old-hash")
	if result != nil || !errors.Is(err, errGenerateToken) || repo.calls != 0 {
		t.Fatal(result, err, repo.calls)
	}
}
