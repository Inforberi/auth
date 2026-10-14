package settings

import (
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func TestCatalog(t *testing.T) {
	input := []Permission{{Key: "reports.read", Name: "Read reports", Group: "Reports"}}
	catalog, err := NewCatalog(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Key = "changed"
	if !catalog.Contains("reports.read") || !catalog.Contains(RolesManage) || !catalog.Contains(EmailBindingManage) || catalog.Contains("unknown") {
		t.Fatal("catalog ownership or core permissions")
	}
	result := catalog.Permissions()
	result[0].Name = "changed"
	if catalog.Permissions()[0].Name == "changed" {
		t.Fatal("mutable catalog leaked")
	}
	for _, input := range [][]Permission{
		{{Key: RolesManage, Name: "Overwrite"}},
		{{Key: "reports.read", Name: "Read"}, {Key: "reports.read", Name: "Duplicate"}},
		{{Key: "reports.*", Name: "Wildcard"}},
		{{Key: "reports.read", Name: ""}},
	} {
		if _, err := NewCatalog(input); !errors.Is(err, domain.ErrInvalidPermission) {
			t.Fatalf("invalid catalog: %v", err)
		}
	}
}
