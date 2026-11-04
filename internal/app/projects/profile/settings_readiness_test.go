package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectnative "github.com/Inforberi/financial-intelligence/internal/app/projects/native"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func TestAssessmentSelectsPotentialMethodsWithoutPublishingCurrentPolicy(t *testing.T) {
	p := &ProjectProfile{policy: settingsdomain.Snapshot{Version: 7, Policy: settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationRequired}}}
	p.selectAssessmentPolicy(ProjectProfileConfig{BrowserEnabled: true, Password: &projectmethods.ProjectPasswordConfig{}, Google: &projectmethods.ProjectOIDCConfig{Enabled: true}})
	require.True(t, p.policy.Policy.Methods.Password)
	require.True(t, p.policy.Policy.Methods.Google)
	require.False(t, p.policy.Policy.Methods.EmailOTP)
	require.EqualValues(t, 7, p.policy.Version)
	require.Equal(t, settingsdomain.VerificationDisabled, p.policy.Policy.PasswordEmailVerification)
	closed := &ProjectProfile{}
	closed.selectAssessmentPolicy(ProjectProfileConfig{})
	require.Equal(t, settingsdomain.PublicMethods{}, closed.policy.Policy.Methods)
	native := &ProjectProfile{}
	native.selectAssessmentPolicy(ProjectProfileConfig{Tokens: &projectnative.ProjectTokenConfig{Enabled: true, Tokens: tokenservice.Config{Native: &tokenservice.NativePolicy{}}, Native: projectnative.ProjectNativeConfig{PasswordEnabled: true}}})
	require.True(t, native.policy.Policy.Methods.Password)
	require.True(t, native.policy.Policy.TokenIssuance.Native)
	require.Nil(t, native.password)
}
