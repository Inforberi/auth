package settings

import (
	"reflect"
	"strings"
	"testing"
)

func TestPreview(t *testing.T) {
	current, err := Load(strings.NewReader(catalogFixture))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := Load(strings.NewReader(strings.ReplaceAll(catalogFixture, "reports.read", "reports.edit")))
	if err != nil {
		t.Fatal(err)
	}
	changes, err := Preview(current, candidate)
	if err != nil || len(changes.AddedPermissions) != 1 || changes.AddedPermissions[0] != "reports.edit" || len(changes.RemovedPermissions) != 1 || changes.RemovedPermissions[0] != "reports.read" || len(changes.ChangedTemplates) != 1 {
		t.Fatalf("preview: %+v %v", changes, err)
	}
	if current.Templates()[0].Permissions[0] != "reports.read" {
		t.Fatal("preview changed current roles")
	}
	changes, err = Preview(current, current)
	if err != nil || !reflect.DeepEqual(changes, Changes{}) {
		t.Fatalf("unchanged preview: %+v %v", changes, err)
	}
	if _, err := Preview(Document{}, candidate); err == nil {
		t.Fatal("unvalidated document accepted")
	}
}
