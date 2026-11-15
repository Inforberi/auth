package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

type Repository interface {
	Rename(context.Context, operatordomain.Principal, domain.Rename) (domain.NameReceipt, error)
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
	runtime   RuntimeObserver
}

func New(repo Repository, authority ReadAuthority) *Catalog {
	return NewWithRuntime(repo, authority, nil)
}

type RuntimeObserver interface {
	Observe(domain.TransitionReceipt)
}

func NewWithRuntime(repo Repository, authority ReadAuthority, runtime RuntimeObserver) *Catalog {
	return &Catalog{repo: repo, authority: authority, runtime: runtime}
}
