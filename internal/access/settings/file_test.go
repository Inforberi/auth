package settings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

const catalogFixture = `{"version":1,"permissions":[{"key":"reports.read","name":"Read reports","group":"Reports"}],"roleTemplates":[{"key":"reader","name":"Reader","permissions":["reports.read"]}]}`

func TestLoadCatalog(t *testing.T) {
	document, err := Load(strings.NewReader(catalogFixture))
	if err != nil {
		t.Fatal(err)
	}
	if !document.Catalog().Contains("reports.read") || !document.Catalog().Contains(RolesManage) {
		t.Fatal("catalog permissions missing")
	}
	roles := document.Templates()
	roles[0].Permissions[0] = "changed"
	if document.Templates()[0].Permissions[0] != "reports.read" {
		t.Fatal("mutable template leaked")
	}
	for _, input := range []string{
		`null`, `{}`, `{"version":2}`, `{"version":1,"unknown":true}`,
		`{"version":1,"version":1}`, `{"version":1,"Version":1}`, `{"version":1,"v\u0065rsion":1}`,
		`{"version":1} {"version":1}`,
		strings.Replace(catalogFixture, `"reports.read"]`, `"unknown"]`, 1),
		strings.Replace(catalogFixture, `"reader"`, `"super_admin"`, 1),
		strings.Replace(catalogFixture, `"reports.read","name"`, `"access.roles.manage","name"`, 1),
		strings.Repeat(" ", MaxCatalogBytes+1),
		string([]byte{0xff}),
	} {
		if _, err := Load(strings.NewReader(input)); err == nil {
			t.Fatalf("invalid catalog accepted: %.80s", input)
		}
	}
}

func TestDocumentBoundsAndOwnership(t *testing.T) {
	definition := Definition{Version: 1, Permissions: []Permission{{Key: "reports.read", Name: "Read reports"}}, RoleTemplates: []RoleTemplate{{Key: "reader", Name: "Reader", Permissions: []domain.PermissionKey{"reports.read"}}}}
	document, err := NewDocument(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.Permissions[0].Name = "changed"
	definition.RoleTemplates[0].Permissions[0] = "changed"
	if document.Catalog().Permissions()[2].Name == "changed" || document.Templates()[0].Permissions[0] != "reports.read" {
		t.Fatal("constructor retained mutable source")
	}
	definition.RoleTemplates = make([]RoleTemplate, MaxRoleTemplates+1)
	if _, err := NewDocument(definition); !errors.Is(err, ErrInvalidCatalog) {
		t.Fatal(err)
	}
	definition.RoleTemplates = []RoleTemplate{{Key: "reader", Name: "Reader"}, {Key: "reader", Name: "Duplicate"}}
	if _, err := NewDocument(definition); !errors.Is(err, ErrInvalidCatalog) {
		t.Fatal(err)
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(catalogFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(filepath.Dir(path)); !errors.Is(err, ErrInvalidCatalog) {
		t.Fatal("directory accepted")
	}
	if _, err := LoadFile(path + ".missing"); err == nil {
		t.Fatal("missing file silently ignored")
	}
	if _, err := LoadFile(""); err != nil {
		t.Fatal("built-in catalog unavailable")
	}
}
