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

func TestAssessmentSelectsPotentialMethodsWithoutPublishingCurrentPolicy(t *testing.T) {
	p := settingsdomain.Snapshot{Version: 7, Policy: settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationRequired}}
	p.Policy = (runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &projectmethods.ProjectPasswordConfig{}, Google: &projectmethods.ProjectOIDCConfig{Enabled: true}}).AssessmentPolicy(p.Policy)
	require.True(t, p.Policy.Methods.Password)
	require.True(t, p.Policy.Methods.Google)
	require.False(t, p.Policy.Methods.EmailOTP)
	require.EqualValues(t, 7, p.Version)
	require.Equal(t, settingsdomain.VerificationDisabled, p.Policy.PasswordEmailVerification)
	closed := settingsdomain.Snapshot{}
	closed.Policy = (runtimeprofile.ProjectProfileConfig{}).AssessmentPolicy(settingsdomain.Policy{})
	require.Equal(t, settingsdomain.PublicMethods{}, closed.Policy.Methods)
	native := settingsdomain.Snapshot{}
	native.Policy = (runtimeprofile.ProjectProfileConfig{Tokens: &projectnative.ProjectTokenConfig{Enabled: true, Tokens: tokenservice.Config{Native: &tokenservice.NativePolicy{}}, Native: projectnative.ProjectNativeConfig{PasswordEnabled: true}}}).AssessmentPolicy(settingsdomain.Policy{})
	require.True(t, native.Policy.Methods.Password)
	require.True(t, native.Policy.TokenIssuance.Native)
}
