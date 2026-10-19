package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type Repository interface {
	Read(context.Context, domain.ID) (domain.Project, error)
	List(context.Context, ListQuery) (Page, error)
	ApplyTransition(context.Context, operatordomain.Principal, domain.Transition) (domain.TransitionReceipt, error)
	Create(context.Context, operatordomain.Principal, domain.Create) (domain.CreationReceipt, error)
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
