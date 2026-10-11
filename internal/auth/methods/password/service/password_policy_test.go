package service

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestNewPasswordPolicyAcrossScenarios(t *testing.T) {
	ctx := context.Background()
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	password := "short"
	_, err := New(nil, nil, nil, nil).Register(ctx, "user@example.com", password, "", "")
	require.ErrorIs(t, err, domain.ErrPasswordTooShort)
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	require.NoError(t, err)
	recovery := NewRecovery(nil, cipher, &recoveryLimit{allow: true}, nil, nil, Config{})
	// Reset проверяет limits раньше политики; остальные зависимости не должны вызываться.
	require.ErrorIs(t, recovery.Reset(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	activation := NewActivation(nil, recovery, accountservice.InvitationConfig{Enabled: true})
	require.ErrorIs(t, activation.Activate(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	protected := NewProtectedRecovery(nil, recovery)
	require.ErrorIs(t, protected.Recover(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	temporary := NewTemporaryPassword(nil, nil, nil, nil, nil, TemporaryPasswordConfig{Enabled: true})
	require.ErrorIs(t, temporary.Complete(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	repo, hash := &mockPasswordRepo{}, &mockHasher{}
	credential := &domain.Credential{UserID: "user", AuthVersion: 1, PasswordHash: "old"}
	repo.On("FindUserByUserID", ctx, credential.UserID).Return(credential, nil).Once()
	hash.On("Compare", "previous", "old").Return(nil).Once()
	svc := New(repo, nil, hash, nil)
	require.ErrorIs(t, svc.ChangePassword(ctx, credential.UserID, "session", "previous", password), domain.ErrPasswordTooShort)
	repo.AssertExpectations(t)
	hash.AssertExpectations(t)
}
