package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type Repository interface {
	Read(context.Context, domain.ID) (domain.Project, error)
	List(context.Context, ListQuery) (Page, error)
}

type ReadAuthority interface {
	AuthorizeRead(context.Context, operatordomain.Principal, operatordomain.Permission) error
}

type Catalog struct {
	repo      Repository
	authority ReadAuthority
}

func New(repo Repository, authority ReadAuthority) *Catalog {
	return &Catalog{repo: repo, authority: authority}
}
