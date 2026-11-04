package methods

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	oidcdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	oidcredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/repository/redis"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsproviders "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type ProjectOIDCDependencies struct {
	Registry *projectruntime.Registry
	Reader   *runtimepostgres.RuntimeCredentialReader
	Redis    *redis.Client
	Clients  *ProjectOIDCClients
}

type ProjectOIDC struct {
	*projectmfa.ProjectMFA
	cfg                          ProjectOIDCConfig
	key                          projectruntime.Key
	deps                         ProjectOIDCDependencies
	flows                        *oidcredis.Repository
	googleCipher, telegramCipher *secretbox.Cipher
}

func NewProjectOIDC(ctx context.Context, key projectruntime.Key, cfg ProjectOIDCConfig, deps ProjectOIDCDependencies) (*ProjectOIDC, error) {
	if err := cfg.validate(deps); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return &ProjectOIDC{cfg: cfg}, nil
	}
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	if err != nil {
		return nil, err
	}
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	if err != nil {
		return nil, err
	}

	cipher, err := secretbox.ForScope(scope, configuration.EncryptionKey(), cfg.Provider+"-login:v1")
	if err != nil {
		return nil, err
	}
	flows, err := oidcredis.NewScoped(deps.Redis, cipher, cfg.Provider, scope)
	if err != nil {
		return nil, err
	}
	google, err := secretbox.ForScope(scope, configuration.EncryptionKey(), "provider-google:v1")
	if err != nil {
		return nil, err
	}
	telegram, err := secretbox.ForScope(scope, configuration.EncryptionKey(), "provider-telegram:v1")
	if err != nil {
		return nil, err
	}
	factory, err := projectmfa.NewProjectMFALogin(scope, configuration.EncryptionKey(), cfg.MFA, cfg.Session, deps.Redis, cfg.Provider)
	if err != nil {
		return nil, err
	}
	var mfa *projectmfa.ProjectMFA
	if factory != nil {
		mfa = projectmfa.BindProjectMFA(factory, key, deps.Registry, deps.Reader, cfg.Timeout, false)
	}
	return &ProjectOIDC{ProjectMFA: mfa, cfg: cfg, key: key, deps: deps, flows: flows, googleCipher: google, telegramCipher: telegram}, nil
}

func (p *ProjectOIDC) use(ctx context.Context, operation func(context.Context, *oidcservice.Service) error) error {
	if !p.cfg.Enabled {
		return oidcdomain.ErrDisabled
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectbinding.RequireCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		service, err := p.service(pool)
		if err != nil {
			return err
		}
		if err := operation(ctx, service); err != nil {
			return err
		}
		return projectbinding.RequireCurrent(ctx, p.deps.Reader, p.key)
	})
}

func (p *ProjectOIDC) service(pool *pgxpool.Pool) (*oidcservice.Service, error) {
	tokens := tokengenerate.New()
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(pool), tokens, p.cfg.Session)
	login := sessionservice.NewLogin(sessions, nil)
	if p.ProjectMFA != nil {
		mfa, err := p.Factory().NewLogin(pool)
		if err != nil {
			return nil, err
		}
		login = sessionservice.NewLogin(sessions, mfa)
	}
	repo := settingspostgres.New(pool)
	policy := settingsservice.New(repo)
	providers := settingsproviders.NewProviders(repo, p.googleCipher, p.telegramCipher)
	cfg := oidcservice.Config{
		Enabled: true, Issuer: settingsdomain.ProviderIssuer(p.cfg.Provider), IPLimit: p.cfg.IPLimit, GlobalLimit: p.cfg.GlobalLimit,
		CheckPolicy: func(ctx context.Context) error { return policy.CheckPublic(ctx, p.cfg.Provider, false) },
	}
	accounts := accountpostgres.New(pool)
	owner := p.deps.Clients.client(p.cfg.Provider)
	service := oidcservice.New(cfg, p.flows, owner, accountservice.NewIdentityResolution(accounts), login, tokens, accountservice.NewIdentityManagement(accounts, p.cfg.Session.FreshAuthTTL))
	return service.WithProviderSource(func(ctx context.Context) (oidcservice.Provider, int64, error) {
		stored, secret, err := projectProviderCredentials(ctx, providers, p.cfg.Provider)
		if err != nil {
			return nil, 0, err
		}
		return owner.WithCredentials(stored.ClientID, secret).WithRedirectURI(p.cfg.RedirectURI), stored.Version, nil
	}), nil
}

func projectProviderCredentials(ctx context.Context, providers *settingsproviders.Providers, name string) (settingsdomain.ProviderSnapshot, string, error) {
	stored, secret, err := providers.Credentials(ctx, name)
	if err != nil {
		return settingsdomain.ProviderSnapshot{}, "", err
	}
	if !stored.SecretSet || stored.ClientID == "" {
		return settingsdomain.ProviderSnapshot{}, "", settingsdomain.ErrMethodNotReady
	}
	return stored, secret, nil
}
