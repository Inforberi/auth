package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func TestValidateSession_SuccessExtended(t *testing.T) {
	repo := &mockRepo{}
	token := &mockTokenHash{}
	clock := &mockClock{}

	token.On("Hash", "RawToken").Return("HashedToken")

	sessionResult := &sessionmodel.Session{
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
		accountmodel.UserID("user-1"),
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
