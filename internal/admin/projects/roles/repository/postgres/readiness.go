package postgres

import (
	"context"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

type Readiness func(context.Context, projectruntime.Key, string) (domain.AuthPolicyReadiness, error)

func (r *RuntimeRoles) WithReadiness(source Readiness) *RuntimeRoles {
	r.readiness = source
	return r
}

func (r *RuntimeRoles) projectMFAReady(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, permission operators.Permission) (bool, error) {
	if r.readiness == nil {
		return false, nil
	}
	selected, err := r.ResolveProjectTarget(ctx, actor, target, permission)
	if err != nil {
		return false, err
	}
	report, err := r.readiness(ctx, selected.Key, selected.Origin)
	if err != nil {
		return false, err
	}
	return report.MFAReady(), nil
}
