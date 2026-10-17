package service

import (
	"testing"

	"github.com/stretchr/testify/mock"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func TestAuthenticateDoesNotCreateSession(t *testing.T) {
	repo, hasher, sessions := &mockPasswordRepo{}, &mockHasher{}, &mockSession{}
	user := accountdomain.UserID("11111111-1111-4111-8111-111111111111")
	repo.On("FindByEmail", mock.Anything, "person@example.test").Return(&passworddomain.Credential{UserID: user, AuthVersion: 3, PasswordHash: "stored hash"}, nil)
	hasher.On("Compare", "Password12345", "stored hash").Return(nil)
	proof, err := newTestService(repo, sessions, hasher).Authenticate(t.Context(), LoginInput{Email: "person@example.test", Password: "Password12345", IP: "192.0.2.1"})
	if err != nil || proof.UserID != user || proof.AuthVersion != 3 || proof.Method != "password" || proof.Reference != "stored hash" || proof.Administrative || proof.VerifiedAt.IsZero() {
		t.Fatal("invalid internal proof", err)
	}
	sessions.AssertNotCalled(t, "BeginLogin", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	sessions.AssertNotCalled(t, "CreateSessionAtVersion", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
}
