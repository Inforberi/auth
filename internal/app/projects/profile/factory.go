package profile

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

type factory struct {
	source runtimeprofile.ProjectProfileSource
	deps   runtimeprofile.ProjectProfileDependencies
}

func NewFactory(deps runtimeprofile.ProjectProfileDependencies, source runtimeprofile.ProjectProfileSource) runtimeprofile.Factory {
	if source == nil || deps.Registry == nil || deps.Reader == nil {
		return nil
	}
	if deps.SMTPTests == nil {
		deps.SMTPTests = settingssmtp.NewSMTPTestGate()
	}
	return &factory{source: source, deps: deps}
}

func (f *factory) Build(ctx context.Context, key projectruntime.Key, origin string) (*runtimeprofile.ProjectProfile, error) {
	cfg, err := f.source(ctx, key, origin)
	if err != nil {
		return nil, err
	}
	return BuildProjectProfile(ctx, key, origin, cfg, f.deps)
}

func (f *factory) Assess(ctx context.Context, key projectruntime.Key, origin string) (projectdomain.AuthPolicyReadiness, error) {
	cfg, err := f.source(ctx, key, origin)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	return AssessProjectProfile(ctx, key, origin, cfg, f.deps)
}

func AssessProjectProfile(ctx context.Context, key projectruntime.Key, origin string, cfg runtimeprofile.ProjectProfileConfig, deps runtimeprofile.ProjectProfileDependencies) (projectdomain.AuthPolicyReadiness, error) {
	return runtimeprofile.AssessWithBuilder(ctx, key, origin, cfg, deps, buildProjectProfile)
}
