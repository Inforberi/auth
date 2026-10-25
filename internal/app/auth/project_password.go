package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

// ProjectPassword borrows process dependencies; each operation holds its own lease.
type ProjectPassword struct {
	mfa          *projectMFALogin
	registration *projectRegistration
	temporary    *projectTemporary
	key          projectruntime.Key
	cfg          ProjectPasswordConfig
	registry     *projectruntime.Registry
	reader       *projectpostgres.RuntimeCredentialReader
	hash         *hasher.Bounded
	limits       *passwordservice.LoginLimit
}

func NewProjectPassword(ctx context.Context, key projectruntime.Key, cfg ProjectPasswordConfig, deps ProjectPasswordDependencies) (*ProjectPassword, error) {
	if err := cfg.validate(deps); err != nil {
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
	cipher, err := (realmSecurity{scope: scope}).cipher(configuration.EncryptionKey(), "password-reset:v1")
	if err != nil {
		return nil, err
	}
	limits, err := passwordredis.NewScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	mfa, err := newProjectMFALogin(scope, configuration.EncryptionKey(), cfg, deps)
	if err != nil {
		return nil, err
	}
	registration, err := newProjectRegistration(scope, configuration.EncryptionKey(), cfg.RegistrationVerification, deps.Redis)
	if err != nil {
		return nil, err
	}
	var temporary *projectTemporary
	if cfg.TemporaryPassword.Enabled {
		temporary = &projectTemporary{limits: limits, digest: cipher.Digest}
	}
	cfg.RegistrationVerification = nil
	return &ProjectPassword{
		mfa: mfa, registration: registration, temporary: temporary,
		key: key, cfg: cfg, registry: deps.Registry, reader: deps.Reader, hash: deps.Hash,
		limits: passwordservice.NewLoginLimit(limits, cipher, cfg.Capacity),
	}, nil
}

func (p *ProjectPassword) Login(ctx context.Context, input passwordservice.LoginInput) (*passwordservice.LoginResult, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	var result *passwordservice.LoginResult
	err := p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.requireCurrent(ctx); err != nil {
			return err
		}
		passwords, err := p.passwordService(pool, passwordpostgres.New(pool))
		if err != nil {
			return err
		}
		result, err = passwords.Login(ctx, input)
		if err != nil {
			return err
		}
		// Keep the pool lease through the final catalog guard; never disclose a token for a stale project.
		return p.requireCurrent(ctx)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) requireCurrent(ctx context.Context) error {
	current, err := p.reader.CurrentRuntimes(ctx, []projectruntime.Key{p.key})
	if err != nil {
		return err
	}
	if !current[0] {
		return projectdomain.ErrConflict
	}
	return nil
}

func (p *ProjectPassword) passwordService(pool *pgxpool.Pool, repo *passwordpostgres.PasswordRepo) (*passwordservice.PasswordService, error) {
	policy := settingsservice.New(settingspostgres.New(pool))
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(pool), tokengenerate.New(), p.cfg.Session)
	login := sessionservice.NewLogin(sessions, nil)
	if p.mfa != nil {
		loginMFA, err := p.mfa.newLogin(pool)
		if err != nil {
			return nil, err
		}
		login = sessionservice.NewLogin(sessions, loginMFA)
	}
	passwords := passwordservice.New(repo, login, p.hash, p.limits).WithPublicPolicy(func(ctx context.Context, registration bool) error {
		return policy.CheckPublic(ctx, "password", registration)
	})
	return passwords, nil
}
