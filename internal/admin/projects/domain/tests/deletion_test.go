package domain_test

import (
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func TestDeletionRequiresExactProjectAndDataLossConfirmation(t *testing.T) {
	id := domain.ID("a2000000-0000-4000-8000-000000000001")
	command := domain.DeletionRequest{
		Target:         domain.DirectoryTarget{ProjectID: id, ExpectedVersion: 1, ExpectedGeneration: 1},
		OperationID:    "b2000000-0000-4000-8000-000000000001",
		ConfirmProject: id,
		ConfirmLoss:    true,
	}
	if err := command.Validate(); err != nil {
		t.Fatal(err)
	}
	wrongProject := command
	wrongProject.ConfirmProject = command.OperationID
	withoutConsent := command
	withoutConsent.ConfirmLoss = false
	for _, invalid := range []domain.DeletionRequest{wrongProject, withoutConsent} {
		if invalid.Validate() == nil {
			t.Fatal("accepted deletion without an exact confirmation")
		}
	}
}
