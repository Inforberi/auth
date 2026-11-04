package profile

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

type (
	BuildProfile func(context.Context, projectruntime.Key, string, ProjectProfileConfig, ProjectProfileDependencies, bool) (*ProjectProfile, error)
	Factory      interface {
		Build(context.Context, projectruntime.Key, string) (*ProjectProfile, error)
		Assess(context.Context, projectruntime.Key, string) (projectdomain.AuthPolicyReadiness, error)
	}
)
