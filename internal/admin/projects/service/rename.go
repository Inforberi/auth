package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func (s *Catalog) Rename(ctx context.Context, actor operatordomain.Principal, input domain.Rename) (domain.NameReceipt, error) {
	command, err := input.Normalize()
	if err != nil {
		return domain.NameReceipt{}, err
	}
	return s.repo.Rename(ctx, actor, command)
}
