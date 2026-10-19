package service

import (
	"errors"
	"strings"
	"testing"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func TestChangeStateUsesCurrentSQLMutationPort(t *testing.T) {
	authority := &readAuthorityStub{err: errors.New("read snapshot must not authorize a mutation")}
	repo := &catalogStub{}
	svc := New(repo, authority)
	actor := operatordomain.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	input := ChangeStateInput{ProjectID: "22222222-2222-4222-8222-222222222222", OperationID: "33333333-3333-4333-8333-333333333333", ExpectedVersion: 7, ExpectedGeneration: 9, Reason: "incident-123"}
	for _, action := range []domain.Action{domain.Suspend, domain.Resume, domain.RetryPreparation} {
		result, err := svc.ChangeState(t.Context(), actor, action, input)
		if err != nil || result.ProjectID != input.ProjectID || repo.actor != actor || repo.command != (domain.Transition{
			ProjectID: input.ProjectID, OperationID: input.OperationID, ExpectedVersion: 7, ExpectedGeneration: 9,
			Action: action, ActorID: domain.ID(actor.UserID), ActorKind: domain.OperatorActor, Reason: input.Reason,
		}) || authority.permission != "" {
			t.Fatal("incorrect SQL command/authority ownership", err)
		}
	}
	repo.err = operatordomain.ErrForbidden
	if _, err := svc.ChangeState(t.Context(), actor, domain.Suspend, input); !errors.Is(err, operatordomain.ErrForbidden) {
		t.Fatal("SQL authority failure lost", err)
	}
}
