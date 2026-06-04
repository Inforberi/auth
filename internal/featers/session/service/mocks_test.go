package session_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
	"github.com/stretchr/testify/mock"
)

var now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
var cfg = config.SessionConfig{
	SessionTTL:              7 * 24 * time.Hour,
	SessionRefreshThreshold: 24 * time.Hour,
	AbsoluteSessionTTL:      14 * 24 * time.Hour,
}

// mock repo
type mockRepo struct{ mock.Mock }

func (m *mockRepo) FindSession(ctx context.Context, tokenHash string) (*session_domain.Session, error) {
	args := m.Called(ctx, tokenHash)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*session_domain.Session), args.Error(1)
}

func (m *mockRepo) CreateSession(
	ctx context.Context,
	sessionParams session_domain.CreateSessionParams,
) error {
	args := m.Called(ctx, sessionParams)
	return args.Error(0)
}

func (m *mockRepo) UpdateSession(
	ctx context.Context,
	tokenHash string,
	session *session_domain.Session,
	ttl time.Duration,
) error {
	args := m.Called(ctx, tokenHash, session, ttl)
	return args.Error(0)
}

func (m *mockRepo) DeleteSession(ctx context.Context, tokenHash string, userID domain.UserID) error {
	args := m.Called(ctx, tokenHash, userID)
	return args.Error(0)
}

func (m *mockRepo) DeleteAllSessions(ctx context.Context, userID domain.UserID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockRepo) DeleteAllSessionsExcept(ctx context.Context, userID domain.UserID, tokenHash string) error {
	args := m.Called(ctx, userID, tokenHash)
	return args.Error(0)
}

// mock token hash
type mockTokenHash struct{ mock.Mock }

func (m *mockTokenHash) GenerateSessionToken() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockTokenHash) Hash(rawToken string) string {
	args := m.Called(rawToken)
	return args.String(0)
}

// mock clock test
type mockClock struct{ mock.Mock }

func (m *mockClock) NowUTC() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}
