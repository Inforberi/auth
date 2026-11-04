package profile_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func TestProfileVerificationSelection(t *testing.T) {
	cfg := runtimeprofile.ProjectProfileConfig{BrowserEnabled: true}
	policy := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Telegram: true}, PasswordEmailVerification: settingsdomain.VerificationOptional}
	require.False(t, cfg.NeedsVerification(settingsdomain.Policy{}))
	require.False(t, cfg.NeedsVerification(policy))
	policy.Methods.Password = true
	require.True(t, cfg.NeedsVerification(policy))
	cfg.BrowserEnabled = false
	require.False(t, cfg.NeedsVerification(policy))
	cfg.Tokens = &projectnative.ProjectTokenConfig{Enabled: true, Tokens: tokenservice.Config{Native: &tokenservice.NativePolicy{}}, Native: projectnative.ProjectNativeConfig{PasswordEnabled: true}}
	require.False(t, cfg.NeedsVerification(policy), "native deployment alone cannot select native issuance")
	policy.TokenIssuance.Native = true
	require.True(t, cfg.NeedsVerification(policy))
	policy.PasswordEmailVerification = settingsdomain.VerificationDisabled
	require.False(t, cfg.NeedsVerification(policy))
}

func TestNativeSelectionPrerequisiteOrder(t *testing.T) {
	cfg := runtimeprofile.ProjectProfileConfig{Tokens: &projectnative.ProjectTokenConfig{Enabled: true, Tokens: tokenservice.Config{Native: &tokenservice.NativePolicy{}}, Native: projectnative.ProjectNativeConfig{PasswordEnabled: true}}}
	cfg.Tokens.Native.EmailOTP.Enabled = true
	policy := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true, EmailOTP: true}, TokenIssuance: settingsdomain.TokenIssuance{Native: true}, PasswordEmailVerification: settingsdomain.VerificationRequired}
	for _, test := range []struct {
		name                        string
		ready                       runtimeprofile.NativeReadiness
		passwordReason, emailReason string
	}{
		{"redis precedes verification and delivery", runtimeprofile.NativeReadiness{}, "redis_unavailable", "redis_unavailable"},
		{"verification and delivery unavailable", runtimeprofile.NativeReadiness{Redis: true}, "verification_unavailable", "delivery_not_running"},
		{"delivery does not block password", runtimeprofile.NativeReadiness{Redis: true, Verification: true}, "", "delivery_not_running"},
		{"verification does not block email", runtimeprofile.NativeReadiness{Redis: true, Delivery: true}, "verification_unavailable", ""},
		{"ready", runtimeprofile.NativeReadiness{Redis: true, Delivery: true, Verification: true}, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := cfg.SelectNative(policy, test.ready)
			require.True(t, selected.Password)
			require.True(t, selected.Email)
			require.Equal(t, test.passwordReason, selected.PasswordReason)
			require.Equal(t, test.emailReason, selected.EmailReason)
			require.True(t, cfg.Tokens.Native.PasswordEnabled, "selection must not mutate the deployment")
			require.True(t, cfg.Tokens.Native.EmailOTP.Enabled)
		})
	}
	policy.TokenIssuance.Native = false
	require.Equal(t, runtimeprofile.NativeSelection{}, cfg.SelectNative(policy, runtimeprofile.NativeReadiness{}))
}

func TestEmailMFARequiresBrowserPasswordRecovery(t *testing.T) {
	cfg := runtimeprofile.ProjectProfileConfig{}
	require.False(t, cfg.EmailMFARecoveryConfigured())
	cfg.Password = &projectmethods.ProjectPasswordConfig{}
	cfg.Password.MFA.Enabled, cfg.Password.MFA.RecoveryEnabled = true, true
	require.False(t, cfg.EmailMFARecoveryConfigured())
	cfg.BrowserEnabled = true
	require.True(t, cfg.EmailMFARecoveryConfigured())
	cfg.Password.MFA.RecoveryEnabled = false
	require.False(t, cfg.EmailMFARecoveryConfigured())
}
