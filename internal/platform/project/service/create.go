package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type CreateInput struct {
	OperationID domain.ID
	Slug        string
	Name        string
	Reason      string
}

func (s *Catalog) Create(ctx context.Context, actor operatordomain.Principal, input CreateInput) (domain.CreationReceipt, error) {
	return s.repo.Create(ctx, actor, domain.Create{OperationID: input.OperationID, Slug: input.Slug, Name: input.Name, Reason: input.Reason})
}
