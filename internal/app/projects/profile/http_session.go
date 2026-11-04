package profile

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type projectHTTPSessions struct {
	profile *ProjectProfile
	cfg     sessionservice.Config
}

func (p *ProjectProfile) httpSessionConfig(fallback *sessionservice.Config) (sessionservice.Config, error) {
	switch {
	case p.password != nil:
		return p.password.BrowserPolicy().Session, nil
	case p.emailOTP != nil:
		return p.emailOTP.BrowserPolicy().Session, nil
	case p.google != nil:
		return p.google.BrowserPolicy().Session, nil
	case p.telegram != nil:
		return p.telegram.BrowserPolicy().Session, nil
	case p.tokens != nil && p.tokens.NativeAvailable():
		policy, _ := p.tokens.SessionPolicy()
		return policy, nil
	case fallback != nil:
		if err := fallback.Validate(); err != nil {
			return sessionservice.Config{}, err
		}
		return *fallback, nil
	default:
		return sessionservice.Config{}, projectdomain.ErrUnavailable
	}
}

func (s *projectHTTPSessions) ValidateSession(ctx context.Context, raw string) (*sessionservice.ValidationResult, error) {
	return s.validate(ctx, raw, true)
}

func (s *projectHTTPSessions) ValidateSessionWithoutRefresh(ctx context.Context, raw string) (*sessionservice.ValidationResult, error) {
	return s.validate(ctx, raw, false)
}

func (s *projectHTTPSessions) validate(ctx context.Context, raw string, refresh bool) (*sessionservice.ValidationResult, error) {
	var result *sessionservice.ValidationResult
	err := s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		sessions := sessionservice.New(clock.UTCClock{}, repo, tokengenerate.New(), s.cfg)
		validate := sessions.ValidateSessionWithoutRefresh
		if refresh {
			validate = sessions.ValidateSession
		}
		var err error
		result, err = validate(ctx, raw)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *projectHTTPSessions) use(ctx context.Context, operation func(context.Context, *sessionpostgres.Repository) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.profile.deps.Registry.UsePool(ctx, s.profile.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectapp.RequireCurrent(ctx, s.profile.deps.Reader, s.profile.key); err != nil {
			return err
		}
		if err := operation(ctx, sessionpostgres.New(pool)); err != nil {
			return err
		}
		return projectapp.RequireCurrent(ctx, s.profile.deps.Reader, s.profile.key)
	})
}
