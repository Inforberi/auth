package access

import (
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
)

func NewProjectAccess(binding projectapp.Binding, catalog accesssettings.Catalog, ready bool) *ProjectAccess {
	return &ProjectAccess{binding: binding, catalog: catalog, mfaReady: ready}
}
