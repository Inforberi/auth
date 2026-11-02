package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
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
