package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type upgradeHasher struct {
	*mockHasher
	needed bool
}

func (h upgradeHasher) NeedsRehash(string) bool { return h.needed }

func TestLoginRehash(t *testing.T) {
	for _, tc := range []struct {
		name             string
		needed           bool
		hashErr, repoErr error
	}{
		{"current", false, nil, nil},
		{"upgrade", true, nil, nil},
		{"busy", true, domain.ErrHashBusy, nil},
		{"cancelled", true, context.Canceled, nil},
		{"storage failure", true, nil, errors.New("storage failure")},
		{"changed password", true, nil, domain.ErrInvalidEmailOrPassword},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			repo, hash, sessions := &mockPasswordRepo{}, &mockHasher{}, &mockSession{}
			credential := &domain.Credential{UserID: "user", AuthVersion: 7, PasswordHash: "old"}
			repo.On("FindByEmail", ctx, "user@example.com").Return(credential, nil).Once()
			hash.On("Compare", "Password123", "old").Return(nil).Once()
			if tc.needed {
				hash.On("GenerateHash", []byte("Password123")).Return("upgraded", tc.hashErr).Once()
				if tc.hashErr == nil {
					repo.On("RehashPassword", ctx, credential.UserID, int64(7), "old", "upgraded").Return(tc.repoErr).Once()
				}
			}
			success := (tc.hashErr == nil || errors.Is(tc.hashErr, domain.ErrHashBusy)) && tc.repoErr == nil
			if success {
				sessions.On("CreateSessionAtVersion", ctx, credential.UserID, "", "", int64(7)).Return(&sessionservice.CreatedSession{RawToken: "session", ExpiresAt: time.Now().Add(time.Hour)}, nil).Once()
			}
			svc := New(repo, sessions, upgradeHasher{hash, tc.needed}, denyLogin{})
			result, err := svc.Login(ctx, LoginInput{Email: "user@example.com", Password: "Password123"})
			if success {
				require.NoError(t, err)
				require.NotNil(t, result)
			} else {
				require.Error(t, err)
				require.Nil(t, result)
			}
			repo.AssertExpectations(t)
			hash.AssertExpectations(t)
			sessions.AssertExpectations(t)
			if !tc.needed {
				hash.AssertNotCalled(t, "GenerateHash", mock.Anything)
			}
		})
	}
}
