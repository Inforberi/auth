package methods

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

func TestProjectEmailOTPDisabled(t *testing.T) {
	service, err := NewProjectEmailOTP(t.Context(), projectruntime.Key{}, ProjectEmailOTPConfig{}, nil, projectbinding.ProjectSMTPDependencies{})
	require.NoError(t, err)
	requested, err := service.Request(t.Context(), "", "")
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, requested)
	session, err := service.Confirm(t.Context(), otpservice.ConfirmInput{})
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, session)
	requested, err = service.RequestReauthentication(t.Context(), mfaservice.Proof{}, "", "")
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, requested)
	reauth, err := service.ConfirmReauthentication(t.Context(), otpservice.ReauthenticationInput{})
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, reauth)
	mfa, err := service.CompleteMFA(t.Context(), mfalogin.CompleteLoginInput{})
	require.ErrorIs(t, err, mfadomain.ErrUnavailable)
	require.Nil(t, mfa)
}
