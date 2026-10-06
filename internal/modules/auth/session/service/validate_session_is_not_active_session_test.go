package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func TestValidateSession_IsNotActiveSession(t *testing.T) {
	tests := []struct {
		name    string
		session *sessionmodel.Session
	}{
		{
			name: "expires_at expired",
			session: &sessionmodel.Session{
				UserID:    "user-1",
				CreatedAt: now.Add(-1 * time.Hour),
				ExpiresAt: now.Add(-1 * time.Minute),
			},
		},
		{
			name: "absolute ttl expired",
			session: &sessionmodel.Session{
				UserID:    "user-1",
				CreatedAt: now.Add(-(cfg.AbsoluteSessionTTL + 1*time.Minute)),
				ExpiresAt: now.Add(1 * 24 * time.Hour),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenHash := &mockTokenHash{}
			clock := &mockClock{}
			repo := &mockRepo{}

			tokenHash.On("Hash", "RawToken").Return("HashedToken")

			sessionResult := &sessionmodel.Session{
				UserID:    "user-1",
				UserAgent: "mobile",
				IPAddress: "12345",
				CreatedAt: tt.session.CreatedAt,
				ExpiresAt: tt.session.ExpiresAt,
			}
			repo.On("FindSession", context.Background(), "HashedToken").Return(sessionResult, nil)

			clock.On("NowUTC").Return(now)

			svc := New(clock, repo, tokenHash, cfg)

			session, err := svc.ValidateSession(context.Background(), "RawToken")

			assert.Error(t, err)
			assert.ErrorIs(t, err, sessionmodel.ErrSessionExpired)
			assert.Nil(t, session)

			repo.AssertNotCalled(
				t,
				"UpdateSession",
				mock.Anything,
				mock.Anything,
				mock.Anything,
				mock.Anything,
			)

			repo.AssertExpectations(t)
			clock.AssertExpectations(t)
			tokenHash.AssertExpectations(t)
		})
	}
}
