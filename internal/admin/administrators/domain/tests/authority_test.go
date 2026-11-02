package domain_test

import (
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
)

func TestRealmAndPermissions(t *testing.T) {
	for _, id := range []domain.RealmID{"", "00000000-0000-0000-0000-000000000000", "not-a-realm", "1C82c477-3a57-4823-8c49-a476550d8a21"} {
		if id.Valid() {
			t.Fatalf("accepted invalid realm %q", id)
		}
	}
	if !domain.RealmID("1c82c477-3a57-4823-8c49-a476550d8a21").Valid() {
		t.Fatal("valid realm rejected")
	}
	seen := map[domain.Permission]bool{}
	for _, p := range domain.OwnerPermissions() {
		if !p.Valid() || seen[p] {
			t.Fatalf("invalid/duplicate owner permission %q", p)
		}
		seen[p] = true
	}
	if len(seen) != 6 || domain.Permission("accounts.users.manage").Valid() || domain.Permission("platform.*").Valid() {
		t.Fatal("platform permission catalog is not explicit")
	}
	permissions := domain.OwnerPermissions()
	permissions[0] = "changed"
	if domain.OwnerPermissions()[0] != domain.ProjectsRead {
		t.Fatal("caller changed shared authority catalog")
	}
}
