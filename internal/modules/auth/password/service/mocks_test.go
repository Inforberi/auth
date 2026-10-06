package service

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func newTestService(repo *mockPasswordRepo, session *mockSession, hash *mockHasher) *PasswordService {
	return New(
		repo,
		session,
		hash,
		nil,
		&mockTokenManager{},
		&mockRedisRepo{},
		passwordmodel.Config{ResetTokenTTL: 1 * time.Hour},
		&mockMailer{},
	)
}

type mockPasswordRepo struct {
	mock.Mock
}

var now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func (m *mockPasswordRepo) FindByEmail(
	ctx context.Context,
	email string,
) (*passwordmodel.FindByEmailResult, error) {
	args := m.Called(ctx, email)

	result, _ := args.Get(0).(*passwordmodel.FindByEmailResult)

	return result, args.Error(1)
}

func (m *mockPasswordRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *mockPasswordRepo) CreateUser(ctx context.Context, email, passwordHash string) (accountmodel.UserID, error) {
	args := m.Called(ctx, email, passwordHash)

	return args.Get(0).(accountmodel.UserID), args.Error(1)
}

func (m *mockPasswordRepo) FindUserByUserID(ctx context.Context, userID accountmodel.UserID) (*passwordmodel.FindUserPassword, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*passwordmodel.FindUserPassword), args.Error(1)
}

func (m *mockPasswordRepo) UpdatePasswordHash(ctx context.Context, userID accountmodel.UserID, passwordHash string) error {
	args := m.Called(ctx, userID, passwordHash)
	return args.Error(0)
}

type mockHasher struct {
	mock.Mock
}

func (m *mockHasher) GenerateHash(password []byte) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *mockHasher) Compare(
	password string,
	encodedHash string,
) error {
	args := m.Called(password, encodedHash)
	return args.Error(0)
}

type mockSession struct {
	mock.Mock
}

func (m *mockSession) CreateSession(
	ctx context.Context,
	userID accountmodel.UserID,
	userAgent string,
	ip string,
) (*sessionmodel.CreatedSession, error) {
	args := m.Called(
		ctx,
		userID,
		userAgent,
		ip,
	)

	session, _ := args.Get(0).(*sessionmodel.CreatedSession)

	return session, args.Error(1)
}

func (m *mockSession) LogoutAllExcept(ctx context.Context, tokenHash string, userID accountmodel.UserID) error {
	args := m.Called(ctx, tokenHash, userID)
	return args.Error(0)
}

type mockTokenManager struct{ mock.Mock }

func (m *mockTokenManager) GenerateToken(lengths ...int) (string, error) {
	args := m.Called(lengths)
	if args.Get(0) == nil {
		return "", args.Error(1)
	}
	return args.String(0), args.Error(1)
}

func (m *mockTokenManager) Hash(rawToken string) string {
	args := m.Called(rawToken)
	return args.String(0)
}

type mockRedisRepo struct{ mock.Mock }

func (m *mockRedisRepo) SaveResetToken(ctx context.Context, tokenHash string, userID accountmodel.UserID, ttl time.Duration) error {
	args := m.Called(ctx, tokenHash, userID, ttl)
	return args.Error(0)
}

type mockMailer struct{ mock.Mock }

func (m *mockMailer) Send(to, subject, htmlBody string) error {
	args := m.Called(to, subject, htmlBody)
	return args.Error(0)
}
