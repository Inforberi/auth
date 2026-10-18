package service

import (
	"context"
	"time"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func (s *Catalog) Read(ctx context.Context, actor operatordomain.Principal, id domain.ID) (domain.Project, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.authority.AuthorizeRead(ctx, actor, operatordomain.ProjectsRead); err != nil {
		return domain.Project{}, err
	}
	return s.repo.Read(ctx, id)
}
