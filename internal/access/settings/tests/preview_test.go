package settings_test

import (
	"reflect"
	"strings"
	"testing"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func TestPreview(t *testing.T) {
	current, err := accesssettings.Load(strings.NewReader(catalogFixture))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := accesssettings.Load(strings.NewReader(strings.ReplaceAll(catalogFixture, "reports.read", "reports.edit")))
	if err != nil {
		t.Fatal(err)
	}
	changes, err := accesssettings.Preview(current, candidate)
	if err != nil || len(changes.AddedPermissions) != 1 || changes.AddedPermissions[0] != "reports.edit" || len(changes.RemovedPermissions) != 1 || changes.RemovedPermissions[0] != "reports.read" || len(changes.ChangedTemplates) != 1 {
		t.Fatalf("preview: %+v %v", changes, err)
	}
	if current.Templates()[0].Permissions[0] != "reports.read" {
		t.Fatal("preview changed current roles")
	}
	changes, err = accesssettings.Preview(current, current)
	if err != nil || !reflect.DeepEqual(changes, accesssettings.Changes{}) {
		t.Fatalf("unchanged preview: %+v %v", changes, err)
	}
	if _, err := accesssettings.Preview(accesssettings.Document{}, candidate); err == nil {
		t.Fatal("unvalidated document accepted")
	}
}
