package tests

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
)

func TestProjectAccountFeaturesDisabledBeforeDependencies(t *testing.T) {
	ctx := t.Context()
	email := &projectaccount.ProjectEmail{}
	require.ErrorIs(t, email.ResendVerification(ctx, "", ""), projectdomain.ErrUnavailable)
	require.ErrorIs(t, email.ConfirmVerification(ctx, "", ""), projectdomain.ErrUnavailable)
	require.ErrorIs(t, email.ForgotPassword(ctx, "", ""), projectdomain.ErrUnavailable)
	require.ErrorIs(t, email.ResetPassword(ctx, "", "", "", ""), projectdomain.ErrUnavailable)
	provision, err := email.ProvisionUser(ctx, accountprovisioning.ProvisionInput{})
	require.ErrorIs(t, err, accountdomain.ErrProvisionDisabled)
	require.Nil(t, provision)
	provision, err = email.ReissueInvitation(ctx, accountprovisioning.InvitationReissueInput{})
	require.ErrorIs(t, err, accountdomain.ErrProvisionDisabled)
	require.Nil(t, provision)
	require.ErrorIs(t, email.ActivateInvitation(ctx, "", "", "", ""), accountdomain.ErrProvisionDisabled)
	expires, err := email.RequestEmailBinding(ctx, accountemail.EmailBindingInput{})
	require.ErrorIs(t, err, accountdomain.ErrEmailBindingDisabled)
	require.True(t, expires.IsZero())
	require.ErrorIs(t, email.ConfirmEmailBinding(ctx, mfaservice.Proof{}, "", ""), accountdomain.ErrEmailBindingDisabled)
	require.ErrorIs(t, email.RequestEmailChange(ctx, "", "", "", "", ""), projectdomain.ErrUnavailable)
	require.ErrorIs(t, email.ConfirmEmailChange(ctx, "", ""), projectdomain.ErrUnavailable)
	require.ErrorIs(t, email.ReportEmailChange(ctx, "", ""), projectdomain.ErrUnavailable)
	require.ErrorIs(t, email.RecoverEmailChange(ctx, "", "", "", ""), projectdomain.ErrUnavailable)
	passwords := &projectmethods.ProjectPassword{}
	temporary, err := passwords.ProvisionTemporaryPassword(ctx, passwordprovisioning.TemporaryProvisionInput{})
	require.ErrorIs(t, err, passworddomain.ErrTemporaryPasswordDisabled)
	require.Nil(t, temporary)
	temporary, err = passwords.ReissueTemporaryPassword(ctx, passwordprovisioning.TemporaryReissueInput{})
	require.ErrorIs(t, err, passworddomain.ErrTemporaryPasswordDisabled)
	require.Nil(t, temporary)
	setup, err := passwords.BeginTemporaryPassword(ctx, "", "", "")
	require.ErrorIs(t, err, passworddomain.ErrTemporaryPasswordDisabled)
	require.Nil(t, setup)
	require.ErrorIs(t, passwords.CompleteTemporaryPassword(ctx, "", "", "", ""), passworddomain.ErrTemporaryPasswordDisabled)
}
