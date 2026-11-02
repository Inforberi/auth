package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type AuthPolicyRepository interface {
	ReadAuthPolicy(context.Context, operatordomain.Principal, domain.DirectoryTarget) (settingsdomain.Snapshot, error)
	UpdateAuthPolicy(context.Context, operatordomain.Principal, domain.AuthPolicyUpdate) (domain.AuthPolicyResult, error)
	ReadAuthPolicyOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.AuthPolicyOutcome, error)
}

type AuthPolicyReadinessRepository interface {
	AuthPolicyRepository
	ReadAuthPolicyView(context.Context, operatordomain.Principal, domain.DirectoryTarget) (domain.AuthPolicyView, error)
}

type AuthPolicy struct {
	repo      AuthPolicyRepository
	readiness AuthPolicyReadinessRepository
}

func NewAuthPolicy(repo AuthPolicyRepository) *AuthPolicy { return &AuthPolicy{repo: repo} }

func NewAuthPolicyWithReadiness(repo AuthPolicyReadinessRepository) *AuthPolicy {
	return &AuthPolicy{repo: repo, readiness: repo}
}

func (s *AuthPolicy) ReadAuthPolicyView(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget) (domain.AuthPolicyView, error) {
	if err := target.Validate(); err != nil {
		return domain.AuthPolicyView{}, err
	}
	if s.readiness == nil {
		return domain.AuthPolicyView{}, domain.ErrUnavailable
	}
	return s.readiness.ReadAuthPolicyView(ctx, actor, target)
}

func (s *AuthPolicy) ReadAuthPolicy(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget) (settingsdomain.Snapshot, error) {
	if err := target.Validate(); err != nil {
		return settingsdomain.Snapshot{}, err
	}
	return s.repo.ReadAuthPolicy(ctx, actor, target)
}

func (s *AuthPolicy) UpdateAuthPolicy(ctx context.Context, actor operatordomain.Principal, command domain.AuthPolicyUpdate) (domain.AuthPolicyResult, error) {
	return s.repo.UpdateAuthPolicy(ctx, actor, command)
}

func (s *AuthPolicy) ReadAuthPolicyOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.AuthPolicyOutcome, error) {
	return s.repo.ReadAuthPolicyOutcome(ctx, actor, project, operation)
}
