package domain_test

import (
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func TestPreparationResourceNames(t *testing.T) {
	r := domain.PreparationReservation{ProjectID: "11111111-1111-4111-8111-111111111111", ReservationID: "11111111-1111-4111-8111-111111111111"}
	database, owner, err := r.ResourceNames()
	if err != nil || database != "authp_11111111111141118111111111111111" || owner != "autho_11111111111141118111111111111111" || len(database) > 63 || len(owner) > 63 {
		t.Fatal("unsafe or unstable resource identifiers", err)
	}
	if strings.Contains(database, "-") || database == owner {
		t.Fatal("resource namespaces overlap")
	}
	r.ReservationID = "22222222-2222-4222-8222-222222222222"
	if next, _, err := r.ResourceNames(); err != nil || next != database {
		t.Fatal("lost reservation could allocate a different database name", err)
	}
	for _, bad := range []domain.ID{"", "00000000-0000-0000-0000-000000000000", "name;DROP DATABASE auth", "ABC"} {
		r.ReservationID = bad
		if _, _, err := r.ResourceNames(); err == nil {
			t.Fatal("untrusted reservation used as SQL identifier")
		}
	}
}
