package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func TestProjectAccessPrerequisitesAndRoutes(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileAccess(t.Context(), ProjectProfileConfig{BrowserEnabled: true})
	require.Empty(t, p.RoutePlan())
	catalog, err := accesssettings.NewCatalog(nil)
	require.NoError(t, err)
	p.buildProfileAccess(t.Context(), ProjectProfileConfig{Access: &catalog})
	require.Equal(t, "browser_disabled", p.states["access_read"].Reason)
	p.buildProfileAccess(t.Context(), ProjectProfileConfig{BrowserEnabled: true, Access: &accesssettings.Catalog{}})
	require.Equal(t, "invalid_catalog", p.states["access_write"].Reason)
	require.Empty(t, p.RoutePlan())
	p.state("access_read", "")
	p.state("access_write", "mfa_unavailable")
	require.Len(t, p.RoutePlan(), 5)
	p.state("access_write", "")
	routes := p.RoutePlan()
	require.Len(t, routes, 11)
	for _, route := range routes {
		require.Equal(t, "session_no_refresh", route.Protection)
	}
}
