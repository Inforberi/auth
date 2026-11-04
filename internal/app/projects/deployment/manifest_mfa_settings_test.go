package deployment

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func TestProjectMFASettingsManifest(t *testing.T) {
	require.False(t, validProjectMethodDeployment(projectMethodDeployment{MFASettings: true}))
	require.True(t, validProjectMethodDeployment(projectMethodDeployment{Browser: true, MFASettings: true}))
	d := &ProjectAuthDeployment{}
	profile := d.browserProfile(projectprofile.ProjectProfileConfig{Password: &projectmethods.ProjectPasswordConfig{}}, projectMethodDeployment{Browser: true, MFASettings: true})
	require.True(t, profile.MFASettingsEnabled)
	require.False(t, (&ProjectAuthDeployment{}).browserProfile(projectprofile.ProjectProfileConfig{}, projectMethodDeployment{}).MFASettingsEnabled)
}
