package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func TestProjectAccountFeaturesDisabledBeforeDependencies(t *testing.T) {
	ctx := t.Context()
	email := &ProjectEmail{}
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
	passwords := &ProjectPassword{}
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

func TestProjectAccountURLScope(t *testing.T) {
	cfg := ProjectEmailConfig{Origin: "https://project.example.test", Invitations: accountprovisioning.InvitationConfig{Enabled: true, URL: "https://project.example.test/activate", TTL: time.Hour, ActivationGlobalLimit: 100, ReissueCooldown: time.Minute, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100}, Change: accountemail.EmailChangeConfig{Enabled: true, ConfirmURL: "https://project.example.test/confirm", ReportURL: "https://project.example.test/report", RecoveryURL: "https://project.example.test/recover", TTL: 30 * time.Minute, ProtectionTTL: 24 * time.Hour, RecoveryTTL: 30 * time.Minute}, FreshAuthTTL: 5 * time.Minute}
	require.NoError(t, cfg.validateAccountFeatures())
	foreign := cfg
	foreign.Invitations.URL = "https://platform.example.test/activate"
	require.Error(t, foreign.validateAccountFeatures())
	foreign = cfg
	foreign.Change.ReportURL = "https://other.example.test/report"
	require.Error(t, foreign.validateAccountFeatures())
	foreign = cfg
	foreign.FreshAuthTTL = 0
	require.Error(t, foreign.validateAccountFeatures())
	cfg.Invitations.Enabled, cfg.Change.Enabled = false, false
	cfg.FreshAuthTTL = 0
	require.NoError(t, cfg.validateAccountFeatures())
}

func TestProjectAccountDeliveryFairnessAcrossSweeps(t *testing.T) {
	seen := [4]int{}
	for turn := uint8(0); turn < 8; turn++ {
		cfg := projectAccountDelivery(turn)
		kinds := []bool{!cfg.EmailChanges && !cfg.Invitations && !cfg.EmailBinding, cfg.EmailChanges, cfg.Invitations, cfg.EmailBinding}
		chosen := 0
		for i, enabled := range kinds {
			if enabled {
				seen[i]++
				chosen++
			}
		}
		require.Equal(t, 1, chosen, "each sweep prioritizes exactly one queue, with verification fallback")
	}
	require.Equal(t, [4]int{2, 2, 2, 2}, seen, "continuous backlog in any queue must not starve another across full sweeps")
}

func TestProjectBindingOnlyNeedsNoPasswordResetURL(t *testing.T) {
	cfg := ProjectEmailConfig{Origin: "https://external.example.test", Binding: accountemail.EmailBindingConfig{Enabled: true, TTL: 5 * time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000}}
	require.NoError(t, cfg.validate())
	cfg.RecoveryEnabled = true
	require.Error(t, cfg.validate(), "enabling password recovery must require its actual config")
}
