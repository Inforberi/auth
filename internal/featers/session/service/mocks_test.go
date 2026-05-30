package session_service

import (
	"context"
	"time"

	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
	"github.com/stretchr/testify/mock"
)

// mock repo
type mockRepo struct{ mock.Mock }

func (m *mockRepo) FindSession(ctx context.Context, tokenHash string) (*session_domain.Session, error) {
	args := m.Called(ctx, tokenHash)
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
