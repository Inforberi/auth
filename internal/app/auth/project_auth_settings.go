package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type projectAuthSettings struct {
	profile *ProjectProfile
	cfg     ProjectProfileConfig
}

func (p *ProjectProfile) buildProfileAuthSettings(cfg ProjectProfileConfig) {
	if !cfg.AuthSettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("auth_settings_read", "browser_disabled")
		p.state("auth_settings_write", "browser_disabled")
		return
	}
	p.authSettings = &projectAuthSettings{profile: p, cfg: cfg}
	p.state("auth_settings_read", "")
	reason := ""
	if p.mfaManagement == nil {
		reason = "mfa_unavailable"
	}
	p.state("auth_settings_write", reason)
}

func (s *projectAuthSettings) use(ctx context.Context, runtime settingsdomain.PolicyRuntime, operation func(context.Context, *settingsservice.Service) (settingsdomain.Snapshot, error)) (settingsdomain.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	var snapshot settingsdomain.Snapshot
	err := p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		var err error
		snapshot, err = operation(ctx, settingsservice.New(settingspostgres.NewWithPolicyRuntime(pool, runtime)))
		if err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
	if err != nil {
		return settingsdomain.Snapshot{}, err
	}
	return snapshot, nil
}

func (s *projectAuthSettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.Snapshot, error) {
	return s.use(ctx, settingsdomain.PolicyRuntime{}, func(ctx context.Context, service *settingsservice.Service) (settingsdomain.Snapshot, error) {
		return service.Read(ctx, actor)
	})
}

func (s *projectAuthSettings) Update(ctx context.Context, input settingsservice.UpdateInput) (settingsdomain.Snapshot, error) {
	snapshot, _, err := s.updateObserved(ctx, input)
	return snapshot, err
}

func (s *projectAuthSettings) updateObserved(ctx context.Context, input settingsservice.UpdateInput) (settingsdomain.Snapshot, projectdomain.AuthPolicyReadiness, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	before, err := s.Read(ctx, input.Actor)
	if err != nil {
		return settingsdomain.Snapshot{}, projectdomain.AuthPolicyReadiness{}, err
	}
	if input.ExpectedVersion > 0 && before.Version != input.ExpectedVersion {
		return settingsdomain.Snapshot{}, projectdomain.AuthPolicyReadiness{}, settingsdomain.ErrPolicyConflict
	}
	p := s.profile
	// Assessment acquires its own leases; the preflight lease is already released.
	view, err := assessProjectProfile(ctx, p.key, p.origin, s.cfg, p.deps)
	if err != nil {
		return settingsdomain.Snapshot{}, projectdomain.AuthPolicyReadiness{}, err
	}
	if view.PolicyVersion != before.Version {
		return settingsdomain.Snapshot{}, projectdomain.AuthPolicyReadiness{}, settingsdomain.ErrPolicyConflict
	}
	snapshot, err := s.use(ctx, view.Runtime, func(ctx context.Context, service *settingsservice.Service) (settingsdomain.Snapshot, error) {
		return service.Update(ctx, input)
	})
	if err != nil {
		return settingsdomain.Snapshot{}, projectdomain.AuthPolicyReadiness{}, err
	}
	return snapshot, view, nil
}
