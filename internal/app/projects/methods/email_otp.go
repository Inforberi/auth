package methods

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type ProjectEmailOTPConfig struct {
	OTP     otpservice.Config
	MFA     mfaservice.Config
	Session sessionservice.Config
	Timeout time.Duration
}

type ProjectEmailOTP struct {
	*projectmfa.ProjectMFA
	cfg    ProjectEmailOTPConfig
	key    projectruntime.Key
	deps   projectapp.ProjectSMTPDependencies
	cipher *secretbox.Cipher
	limits *passwordredis.RedisRepo
}

func NewProjectEmailOTP(ctx context.Context, key projectruntime.Key, cfg ProjectEmailOTPConfig, allowed []string, deps projectapp.ProjectSMTPDependencies) (*ProjectEmailOTP, error) {
	cfg.OTP.CheckPolicy = nil
	if !cfg.OTP.Enabled && !cfg.OTP.ReauthenticationEnabled {
		return &ProjectEmailOTP{cfg: cfg}, nil
	}
	if deps.Registry == nil || deps.Reader == nil || deps.Redis == nil || cfg.Timeout <= 0 || cfg.Timeout > 30*time.Second {
		return nil, errors.New("invalid project email OTP dependencies/timeout")
	}
	if err := cfg.OTP.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Session.Validate(); err != nil {
		return nil, err
	}
	if err := projectmfa.ValidateProjectMFA(cfg.MFA); err != nil {
		return nil, err
	}
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	if err != nil {
		return nil, err
	}
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	if err != nil {
		return nil, err
	}
	cipher, err := secretbox.ForScope(scope, configuration.EncryptionKey(), "email-login:v1")
	if err != nil {
		return nil, err
	}
	limits, err := passwordredis.NewScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	smtp, err := projectapp.NewSMTP(key, configuration.EncryptionKey(), allowed, deps)
	if err != nil {
		return nil, err
	}
	if _, err := smtp.Credentials(ctx); err != nil {
		return nil, err
	}
	factory, err := projectmfa.NewProjectMFALogin(scope, configuration.EncryptionKey(), cfg.MFA, cfg.Session, deps.Redis, "emailotp")
	if err != nil {
		return nil, err
	}
	var mfa *projectmfa.ProjectMFA
	if factory != nil {
		mfa = projectmfa.BindProjectMFA(factory, key, deps.Registry, deps.Reader, cfg.Timeout, false)
	}
	return &ProjectEmailOTP{ProjectMFA: mfa, cfg: cfg, key: key, deps: deps, cipher: cipher, limits: limits}, nil
}

func (p *ProjectEmailOTP) use(ctx context.Context, operation func(context.Context, *otpservice.Service) error) error {
	if !p.cfg.OTP.Enabled && !p.cfg.OTP.ReauthenticationEnabled {
		return otpdomain.ErrDisabled
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectapp.RequireCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		tokens := tokengenerate.New()
		sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(pool), tokens, p.cfg.Session)
		login := sessionservice.NewLogin(sessions, nil)
		if p.ProjectMFA != nil {
			mfa, err := p.Factory().NewLogin(pool)
			if err != nil {
				return err
			}
			login = sessionservice.NewLogin(sessions, mfa)
		}
		cfg := p.cfg.OTP
		policy := settingsservice.New(settingspostgres.New(pool))
		cfg.CheckPolicy = func(ctx context.Context) error { return policy.CheckPublic(ctx, "emailotp", false) }
		service := otpservice.New(otppostgres.New(pool), p.cipher, p.limits, login, tokens, cfg)
		if err := operation(ctx, service); err != nil {
			return err
		}
		return projectapp.RequireCurrent(ctx, p.deps.Reader, p.key)
	})
}
