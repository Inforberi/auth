package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func TestProjectAccessPrerequisitesAndRoutes(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileAccess(t.Context(), runtimeprofile.ProjectProfileConfig{BrowserEnabled: true})
	catalog, err := accesssettings.NewCatalog(nil)
	require.NoError(t, err)
	p.buildProfileAccess(t.Context(), runtimeprofile.ProjectProfileConfig{Access: &catalog})
	require.Equal(t, "browser_disabled", p.states["access_read"].Reason)
	p.buildProfileAccess(t.Context(), runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Access: &accesssettings.Catalog{}})
	require.Equal(t, "invalid_catalog", p.states["access_write"].Reason)
}
