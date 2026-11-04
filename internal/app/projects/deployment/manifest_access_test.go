package deployment

import (
	"testing"

	"github.com/stretchr/testify/require"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func TestProjectAccessCatalogRejectsDuplicateOrInvalidPermissions(t *testing.T) {
	_, err := compileProjectAccess(&projectAccessDeployment{Permissions: []accesssettings.Permission{{Key: accesssettings.RolesManage, Name: "Override"}}})
	require.ErrorIs(t, err, errProjectAuthManifest)
	_, err = compileProjectAccess(&projectAccessDeployment{Permissions: []accesssettings.Permission{{Key: "*", Name: "Everything"}}})
	require.ErrorIs(t, err, errProjectAuthManifest)
}
