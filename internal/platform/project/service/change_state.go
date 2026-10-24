package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type ChangeStateInput struct {
	ProjectID          domain.ID
	OperationID        domain.ID
	ExpectedVersion    int64
	ExpectedGeneration int64
	Reason             string
}

func (s *Catalog) ChangeState(ctx context.Context, actor operatordomain.Principal, action domain.Action, input ChangeStateInput) (domain.TransitionReceipt, error) {
	result, err := s.repo.ApplyTransition(ctx, actor, domain.Transition{
		ProjectID: input.ProjectID, OperationID: input.OperationID,
		ExpectedVersion: input.ExpectedVersion, ExpectedGeneration: input.ExpectedGeneration,
		Action: action, ActorKind: domain.OperatorActor, ActorID: domain.ID(actor.UserID), Reason: input.Reason,
	})
	if err != nil {
		return domain.TransitionReceipt{}, err
	}
	if s.runtime != nil {
		s.runtime.Observe(result)
	}
	return result, nil
}
