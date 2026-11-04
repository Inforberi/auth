package settings_test

import (
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func TestCatalog(t *testing.T) {
	input := []accesssettings.Permission{{Key: "reports.read", Name: "Read reports", Group: "Reports"}}
	catalog, err := accesssettings.NewCatalog(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Key = "changed"
	if !catalog.Contains("reports.read") || !catalog.Contains(accesssettings.RolesManage) || !catalog.Contains(accesssettings.EmailBindingManage) || !catalog.Contains(accesssettings.UsersManage) || !catalog.Contains(accesssettings.UsersRead) || !catalog.Contains(accesssettings.UsersStatusManage) || !catalog.Contains(accesssettings.UsersDelete) || catalog.Contains("unknown") {
		t.Fatal("catalog ownership or core permissions")
	}
	result := catalog.Permissions()
	result[0].Name = "changed"
	if catalog.Permissions()[0].Name == "changed" {
		t.Fatal("mutable catalog leaked")
	}
	for _, input := range [][]accesssettings.Permission{
		{{Key: accesssettings.RolesManage, Name: "Overwrite"}},
		{{Key: accesssettings.UsersManage, Name: "Overwrite"}},
		{{Key: accesssettings.UsersRead, Name: "Overwrite"}},
		{{Key: accesssettings.UsersStatusManage, Name: "Overwrite"}},
		{{Key: accesssettings.UsersDelete, Name: "Overwrite"}},
		{{Key: accesssettings.AuthSettingsManage, Name: "Overwrite"}},
		{{Key: "reports.read", Name: "Read"}, {Key: "reports.read", Name: "Duplicate"}},
		{{Key: "reports.*", Name: "Wildcard"}},
		{{Key: "reports.read", Name: ""}},
	} {
		if _, err := accesssettings.NewCatalog(input); !errors.Is(err, domain.ErrInvalidPermission) {
			t.Fatalf("invalid catalog: %v", err)
		}
	}
}
