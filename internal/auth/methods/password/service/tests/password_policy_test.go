package service_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestNewPasswordPolicyAcrossScenarios(t *testing.T) {
	ctx := context.Background()
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	password := "short"
	_, err := passwordservice.New(nil, nil, nil, nil).Register(ctx, "user@example.com", password, "", "")
	require.ErrorIs(t, err, domain.ErrPasswordTooShort)
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	require.NoError(t, err)
	recovery := passwordrecovery.NewRecovery(nil, cipher, &recoveryLimit{allow: true}, nil, nil, passwordrecovery.Config{})
	// Reset проверяет limits раньше политики; остальные зависимости не должны вызываться.
	require.ErrorIs(t, recovery.Reset(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	activation := passwordprovisioning.NewActivation(nil, nil, &recoveryLimit{allow: true}, cipher.Digest, accountprovisioning.InvitationConfig{Enabled: true})
	require.ErrorIs(t, activation.Activate(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	protected := passwordrecovery.NewProtectedRecovery(nil, recovery)
	require.ErrorIs(t, protected.Recover(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	temporary := passwordprovisioning.NewTemporaryPassword(nil, nil, nil, nil, nil, passwordprovisioning.TemporaryPasswordConfig{Enabled: true})
	require.ErrorIs(t, temporary.Complete(ctx, token, password, password, "ip"), domain.ErrPasswordTooShort)
	repo, hash := &mockPasswordRepo{}, &mockHasher{}
	credential := &domain.Credential{UserID: "user", AuthVersion: 1, PasswordHash: "old"}
	repo.On("FindUserByUserID", ctx, credential.UserID).Return(credential, nil).Once()
	hash.On("Compare", "previous", "old").Return(nil).Once()
	svc := passwordservice.New(repo, nil, hash, nil)
	require.ErrorIs(t, svc.ChangePassword(ctx, credential.UserID, "session", "previous", password), domain.ErrPasswordTooShort)
	repo.AssertExpectations(t)
	hash.AssertExpectations(t)
}
