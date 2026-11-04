package access

import (
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

func NewProjectAccess(binding projectbinding.Binding, catalog accesssettings.Catalog, ready bool) *ProjectAccess {
	return &ProjectAccess{binding: binding, catalog: catalog, mfaReady: ready}
}
