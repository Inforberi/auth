package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func TestAdministratorLoginProofAndErrors(t *testing.T) {
	for _, failure := range []error{nil, mfadomain.ErrProofRequired, mfadomain.ErrConflict, sessiondomain.ErrMFARequired, errors.New("storage failure")} {
		repo, hash, sessions := &mockPasswordRepo{}, &mockHasher{}, &mockSession{}
		repo.On("FindByEmail", mock.Anything, "admin@example.test").Return(&passworddomain.Credential{UserID: "admin", AuthVersion: 7, PasswordHash: "verified-hash"}, nil)
		hash.On("Compare", "Password12345", "verified-hash").Return(nil)
		sessions.On("CreateSessionAtVersion", mock.Anything, accountdomain.UserID("admin"), "agent", "ip", int64(7)).Return(&sessionservice.CreatedSession{}, failure)
		result, err := newTestService(repo, sessions, hash).LoginAdministrator(context.Background(), LoginInput{Email: "admin@example.test", Password: "Password12345", UserAgent: "agent", IP: "ip"})
		if !sessions.primary.Administrative || sessions.primary.Method != "password" || sessions.primary.Reference != "verified-hash" {
			t.Fatal("administrative proof lost", sessions.primary)
		}
		if failure == nil {
			if err != nil || result == nil {
				t.Fatal(err)
			}
			continue
		}
		if result != nil {
			t.Fatal("failed login returned result")
		}
		if errors.Is(failure, mfadomain.ErrProofRequired) || errors.Is(failure, mfadomain.ErrConflict) || errors.Is(failure, sessiondomain.ErrMFARequired) {
			if !errors.Is(err, passworddomain.ErrInvalidEmailOrPassword) {
				t.Fatal("eligibility leaked", err)
			}
		} else if !errors.Is(err, failure) {
			t.Fatal("storage failure hidden", err)
		}
		repo.AssertExpectations(t)
		hash.AssertExpectations(t)
		sessions.AssertExpectations(t)
	}
}
