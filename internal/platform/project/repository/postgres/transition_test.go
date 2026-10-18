package postgres

import (
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func TestTransitionRejectsInvalidCommandBeforeStorage(t *testing.T) {
	if _, err := Transition(t.Context(), nil, domain.Transition{}); !errors.Is(err, domain.ErrInvalidProject) {
		t.Fatal("invalid transition reached storage", err)
	}
	c := domain.Transition{ProjectID: "1c82c477-3a57-4823-8c49-a476550d8a21", OperationID: "11111111-1111-4111-8111-111111111111", ActorID: "22222222-2222-4222-8222-222222222222", ActorKind: domain.OperatorActor, Action: domain.Suspend, ExpectedVersion: 1, ExpectedGeneration: 1, Reason: "fixture"}
	if _, err := Transition(t.Context(), nil, c); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("missing transaction accepted", err)
	}
}
