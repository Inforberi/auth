package service

import (
	"context"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type AuthPolicyRepository interface {
	ReadAuthPolicy(context.Context, operatordomain.Principal, domain.DirectoryTarget) (settingsdomain.Snapshot, error)
	UpdateAuthPolicy(context.Context, operatordomain.Principal, domain.AuthPolicyUpdate) (domain.AuthPolicyResult, error)
	ReadAuthPolicyOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.AuthPolicyOutcome, error)
}

type AuthPolicy struct{ repo AuthPolicyRepository }

func NewAuthPolicy(repo AuthPolicyRepository) *AuthPolicy { return &AuthPolicy{repo: repo} }

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
