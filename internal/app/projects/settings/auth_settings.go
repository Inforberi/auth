package settings

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type ProjectAuthSettings struct {
	binding projectapp.Binding
	timeout time.Duration
	assess  func(context.Context) (projectdomain.AuthPolicyReadiness, error)
}

func (s *ProjectAuthSettings) use(ctx context.Context, runtime settingsdomain.PolicyRuntime, operation func(context.Context, *settingsservice.Service) (settingsdomain.Snapshot, error)) (settingsdomain.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.binding
	var snapshot settingsdomain.Snapshot
	err := p.Registry.UsePool(ctx, p.Key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectapp.RequireCurrent(ctx, p.Reader, p.Key); err != nil {
			return err
		}
		var err error
		snapshot, err = operation(ctx, settingsservice.New(settingspostgres.NewWithPolicyRuntime(pool, runtime)))
		if err != nil {
			return err
		}
		return projectapp.RequireCurrent(ctx, p.Reader, p.Key)
	})
	if err != nil {
		return settingsdomain.Snapshot{}, err
	}
	return snapshot, nil
}

func (s *ProjectAuthSettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.Snapshot, error) {
	return s.use(ctx, settingsdomain.PolicyRuntime{}, func(ctx context.Context, service *settingsservice.Service) (settingsdomain.Snapshot, error) {
		return service.Read(ctx, actor)
	})
}

func (s *ProjectAuthSettings) Update(ctx context.Context, input settingsservice.UpdateInput) (settingsdomain.Snapshot, error) {
	snapshot, _, err := s.updateObserved(ctx, input)
	return snapshot, err
}

func (s *ProjectAuthSettings) updateObserved(ctx context.Context, input settingsservice.UpdateInput) (settingsdomain.Snapshot, projectdomain.AuthPolicyReadiness, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	before, err := s.Read(ctx, input.Actor)
	if err != nil {
		return settingsdomain.Snapshot{}, projectdomain.AuthPolicyReadiness{}, err
	}
	if input.ExpectedVersion > 0 && before.Version != input.ExpectedVersion {
		return settingsdomain.Snapshot{}, projectdomain.AuthPolicyReadiness{}, settingsdomain.ErrPolicyConflict
	}
	// Assessment acquires its own leases; the preflight lease is already released.
	view, err := s.assess(ctx)
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
