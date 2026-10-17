package service

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

var (
	now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg = Config{
		SessionTTL:              7 * 24 * time.Hour,
		SessionRefreshThreshold: 24 * time.Hour,
		AbsoluteSessionTTL:      14 * 24 * time.Hour,
	}
)

type mockRepo struct{ mock.Mock }

func (m *mockRepo) FindSession(ctx context.Context, tokenHash string) (*sessiondomain.Session, error) {
	args := m.Called(ctx, tokenHash)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*sessiondomain.Session), args.Error(1)
}

func (m *mockRepo) CreateSession(
	ctx context.Context,
	sessionParams CreateSessionParams,
) (time.Time, error) {
	args := m.Called(ctx, sessionParams)
	return args.Get(0).(time.Time), args.Error(1)
}

func (m *mockRepo) RefreshSession(
	ctx context.Context,
	tokenHash string,
	session *sessiondomain.Session,
	expectedExpiry time.Time,
) (bool, error) {
	args := m.Called(ctx, tokenHash, session, expectedExpiry)
	return args.Bool(0), args.Error(1)
}

type mockTokenHash struct{ mock.Mock }

func (m *mockTokenHash) GenerateToken(lengths ...int) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockTokenHash) Hash(rawToken string) string {
	args := m.Called(rawToken)
	return args.String(0)
}

type mockClock struct{ mock.Mock }

func (m *mockClock) NowUTC() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}
