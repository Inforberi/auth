package session_service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func TestCreateSession_Success(t *testing.T) {
	userAgent := "mobile"
	ip := "12345"

	cfg := config.SessionConfig{
		SessionTTL:              7 * 24 * time.Hour,
		SessionRefreshThreshold: 24 * time.Hour,
		AbsoluteSessionTTL:      14 * 24 * time.Hour,
	}

	repo := &mockRepo{}
	token := &mockTokenHash{}
	clock := &mockClock{}

	token.
		On("GenerateSessionToken").
		Return("RawToken", nil)

	token.
		On("Hash", "RawToken").
		Return("HashedToken", nil)

	expected := session_domain.CreateSessionParams{
		UserID:    "user-1",
		CreatedAt: now,
		ExpiresAt: now.Add(cfg.SessionTTL),
		TokenHash: "HashedToken",
		UserAgent: userAgent,
		IPAddress: ip,
	}

	clock.
		On("NowUTC").
		Return(now)

	repo.
		On(
			"CreateSession",
			mock.Anything,
			expected,
		).
		Return(nil)

	svc := New(clock, repo, token, cfg)

	session, err := svc.CreateSession(
		context.Background(),
		"user-1",
		userAgent,
		ip,
	)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(
		t,
		"RawToken",
		session.RawToken,
	)
	assert.Equal(
		t,
		now.Add(cfg.SessionTTL),
		session.ExpiresAt,
	)
	repo.AssertExpectations(t)
	token.AssertExpectations(t)
	clock.AssertExpectations(t)
}

var errGenerateToken = errors.New("err generate token")

func TestCreateSession_TokenError(t *testing.T) {
	token := &mockTokenHash{}
	clock := &mockClock{}
	repo := &mockRepo{}

	cfg := config.SessionConfig{
		SessionTTL:              7 * 24 * time.Hour,
		SessionRefreshThreshold: 24 * time.Hour,
		AbsoluteSessionTTL:      14 * 24 * time.Hour,
	}

	token.On("GenerateSessionToken").Return("", errGenerateToken)

	svc := New(clock, repo, token, cfg)

	session, err := svc.CreateSession(
		context.Background(),
		"user-1",
		"mobile",
		"12345",
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, errGenerateToken)
	assert.Nil(t, session)

	token.AssertCalled(
		t,
		"GenerateSessionToken",
	)
	token.AssertNotCalled(
		t,
		"Hash",
		mock.Anything,
	)
	clock.AssertNotCalled(
		t,
		"NowUTC",
	)
	repo.AssertNotCalled(
		t,
		"CreateSession",
		mock.Anything,
		mock.Anything,
	)
}

var ErrCreateSession = errors.New("error create session")

func TestCreateSession_CreateSessionError(t *testing.T) {
	cfg := config.SessionConfig{
		SessionTTL:              7 * 24 * time.Hour,
		AbsoluteSessionTTL:      14 * 24 * time.Hour,
		SessionRefreshThreshold: 24 * time.Hour,
	}

	token := &mockTokenHash{}
	clock := &mockClock{}
	repo := &mockRepo{}

	token.On("GenerateSessionToken").Return("RawToken", nil)
	token.On("Hash", "RawToken").Return("HashedToken")

	clock.On("NowUTC").Return(now)

	repo.On("CreateSession", mock.Anything, mock.Anything).Return(ErrCreateSession)

	svc := New(clock, repo, token, cfg)

	session, err := svc.CreateSession(
		context.Background(),
		"user-1",
		"mobile",
		"12345",
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCreateSession)
	assert.Nil(t, session)

	repo.AssertExpectations(t)
	token.AssertExpectations(t)
	clock.AssertExpectations(t)
}
