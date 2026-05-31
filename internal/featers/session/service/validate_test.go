package session_service

import (
	"context"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestValidateSession_SuccessNoExtended(t *testing.T) {
	repo := &mockRepo{}
	token := &mockTokenHash{}
	clock := &mockClock{}

	token.On("Hash", "RawToken").Return("HashedToken")

	sessionResult := &session_domain.Session{
		UserID:    "user-1",
		UserAgent: "mobile",
		IPAddress: "12345",
		CreatedAt: now.Add(-5 * time.Hour),
		ExpiresAt: now.Add(5 * 24 * time.Hour),
	}
	repo.On("FindSession", context.Background(), "HashedToken").Return(sessionResult, nil)

	clock.On("NowUTC").Return(now)

	svc := New(clock, repo, token, cfg)

	session, err := svc.ValidateSession(context.Background(), "RawToken")

	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(
		t,
		domain.UserID("user-1"),
		session.UserID,
	)

	assert.Equal(
		t,
		sessionResult.ExpiresAt,
		session.ExpiresAt,
	)

	assert.False(
		t,
		session.Extended,
	)

	token.AssertExpectations(t)
	repo.AssertExpectations(t)
	clock.AssertExpectations(t)
}

func TestValidateSession_SuccessExtended(t *testing.T) {
	repo := &mockRepo{}
	token := &mockTokenHash{}
	clock := &mockClock{}

	token.On("Hash", "RawToken").Return("HashedToken")

	sessionResult := &session_domain.Session{
		UserID:    "user-1",
		UserAgent: "mobile",
		IPAddress: "12345",
		CreatedAt: now.Add(-5 * time.Hour),
		ExpiresAt: now.Add(12 * time.Hour),
	}
	repo.On("FindSession", context.Background(), "HashedToken").Return(sessionResult, nil)
	repo.On("UpdateSession", context.Background(), "HashedToken", sessionResult, cfg.SessionTTL).Return(nil)

	clock.On("NowUTC").Return(now)

	svc := New(clock, repo, token, cfg)

	session, err := svc.ValidateSession(context.Background(), "RawToken")

	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(
		t,
		domain.UserID("user-1"),
		session.UserID,
	)

	assert.Equal(
		t,
		now.Add(cfg.SessionTTL),
		session.ExpiresAt,
	)

	assert.True(
		t,
		session.Extended,
	)

	token.AssertExpectations(t)
	repo.AssertExpectations(t)
	clock.AssertExpectations(t)
}

func TestValidateSession_ErrFindSession(t *testing.T) {
	clock := &mockClock{}
	token := &mockTokenHash{}
	repo := &mockRepo{}

	token.On("Hash", "RawToken").Return("HashedToken")

	repo.On("FindSession", context.Background(), "HashedToken").Return(nil, session_domain.ErrSessionNotFound)

	svc := New(clock, repo, token, cfg)

	session, err := svc.ValidateSession(context.Background(), "RawToken")

	assert.Error(t, err)
	assert.ErrorIs(t, err, session_domain.ErrSessionNotFound)
	assert.Nil(t, session)

	clock.AssertNotCalled(t, "NowUTC")

	repo.AssertNotCalled(
		t,
		"UpdateSession",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)

	repo.AssertExpectations(t)

	token.AssertExpectations(t)
}

func TestValidateSession_IsNotActiveSession(t *testing.T) {
	tests := []struct {
		name    string
		session *session_domain.Session
	}{
		{
			name: "expires_at expired",
			session: &session_domain.Session{
				UserID:    "user-1",
				CreatedAt: now.Add(-1 * time.Hour),
				ExpiresAt: now.Add(-1 * time.Minute),
			},
		},
		{
			name: "absolute ttl expired",
			session: &session_domain.Session{
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

			sessionResult := &session_domain.Session{
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
			assert.ErrorIs(t, err, session_domain.ErrSessionExpired)
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
