package service

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func newTestService(repo *mockPasswordRepo, session *mockSession, hash *mockHasher) *PasswordService {
	return New(repo, session, hash, denyLogin{})
}

func (m *mockPasswordRepo) ChangePassword(ctx context.Context, id accountdomain.UserID, session, expectedHash, newHash string) error {
	return m.Called(ctx, id, session, expectedHash, newHash).Error(0)
}

type mockPasswordRepo struct {
	mock.Mock
}

var now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func (m *mockPasswordRepo) FindByEmail(
	ctx context.Context,
	email string,
) (*passworddomain.Credential, error) {
	args := m.Called(ctx, email)

	result, _ := args.Get(0).(*passworddomain.Credential)

	return result, args.Error(1)
}

func (m *mockPasswordRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *mockPasswordRepo) CreateUser(ctx context.Context, email, passwordHash string) (accountdomain.UserID, error) {
	args := m.Called(ctx, email, passwordHash)

	return args.Get(0).(accountdomain.UserID), args.Error(1)
}

func (m *mockPasswordRepo) FindUserByUserID(ctx context.Context, userID accountdomain.UserID) (*passworddomain.Credential, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*passworddomain.Credential), args.Error(1)
}

type mockHasher struct {
	mock.Mock
}

func (m *mockHasher) NeedsRehash(string) bool { return false }

func (m *mockPasswordRepo) RehashPassword(ctx context.Context, id accountdomain.UserID, version int64, expectedHash, newHash string) error {
	return m.Called(ctx, id, version, expectedHash, newHash).Error(0)
}

func (m *mockHasher) GenerateHash(_ context.Context, password []byte) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *mockHasher) Compare(
	_ context.Context,
	password string,
	encodedHash string,
) error {
	args := m.Called(password, encodedHash)
	return args.Error(0)
}

type mockSession struct {
	mock.Mock
	primary mfaservice.PrimaryProof
}

func (m *mockSession) BeginLogin(ctx context.Context, proof mfaservice.PrimaryProof, agent, ip string) (*sessionservice.CreatedSession, error) {
	m.primary = proof
	return m.CreateSessionAtVersion(ctx, proof.UserID, agent, ip, proof.AuthVersion)
}

func (m *mockSession) CreateSessionAtVersion(ctx context.Context, id accountdomain.UserID, agent, ip string, version int64) (*sessionservice.CreatedSession, error) {
	args := m.Called(ctx, id, agent, ip, version)
	result, _ := args.Get(0).(*sessionservice.CreatedSession)
	return result, args.Error(1)
}
