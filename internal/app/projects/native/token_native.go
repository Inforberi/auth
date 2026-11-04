package native

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type projectNative struct {
	mfa         *projectmfa.ProjectMFALogin
	password    *passwordservice.LoginLimit
	limits      *passwordredis.RedisRepo
	emailCipher *secretbox.Cipher
	emailMFA    *projectmfa.ProjectEmailMFA
}

func newProjectNative(ctx context.Context, key projectruntime.Key, scope realmscope.Scope, root string, cfg ProjectTokenConfig, deps ProjectTokenDependencies) (*projectNative, error) {
	if cfg.Tokens.Native == nil {
		return nil, nil
	}

	mfa, err := projectmfa.NewProjectMFALogin(scope, root, cfg.Native.MFA, cfg.Tokens.Native.Sessions, deps.Redis, "password")
	if err != nil {
		return nil, err
	}
	passwordEnabled, emailEnabled := cfg.Native.PasswordEnabled, cfg.Native.EmailOTP.Enabled
	mfa.BindPrimary(func(method, issuer string) bool {
		return issuer == "" && (method == "password" && passwordEnabled || method == "emailotp" && emailEnabled)
	})
	limits, err := passwordredis.NewScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	native := &projectNative{mfa: mfa, limits: limits}
	if passwordEnabled {
		cipher, err := secretbox.ForScope(scope, root, "password-reset:v1")
		if err != nil {
			return nil, err
		}
		native.password = passwordservice.NewLoginLimit(limits, cipher, cfg.Native.Capacity)
	}
	if emailEnabled {
		native.emailCipher, err = secretbox.ForScope(scope, root, "email-login:v1")
		if err != nil {
			return nil, err
		}
		smtp, err := projectapp.NewSMTP(key, root, cfg.Native.SMTPAllowedTargets, projectapp.ProjectSMTPDependencies{Registry: deps.Registry, Reader: deps.Reader, Redis: deps.Redis})
		if err != nil {
			return nil, err
		}
		if _, err := smtp.Credentials(ctx); err != nil {
			return nil, err
		}
	}
	return native, nil
}

func (p *ProjectTokens) nativeLogin(pool *pgxpool.Pool, service *tokenservice.Service) (*tokenservice.NativeLogin, *mfalogin.Login, error) {
	mfa, err := p.native.mfa.NewLogin(pool)
	if err != nil {
		return nil, nil, err
	}
	selected, err := p.native.mfa.NewSelectedLogin(pool)
	if err != nil {
		return nil, nil, err
	}
	login, err := tokenservice.NewNativeLogin(service, selected)
	return login, mfa, err
}

func (p *ProjectTokens) nativePassword(pool *pgxpool.Pool, service *tokenservice.Service) (*tokenservice.NativePasswordLogin, error) {
	login, _, err := p.nativeLogin(pool, service)
	if err != nil {
		return nil, err
	}
	policy := settingsservice.New(settingspostgres.New(pool))
	passwords := passwordservice.New(passwordpostgres.New(pool), nil, p.deps.Hash, p.native.password).WithPublicPolicy(func(ctx context.Context, registration bool) error {
		return policy.CheckPublic(ctx, "password", registration)
	})
	return tokenservice.NewNativePasswordLogin(login, passwords)
}

func (p *ProjectTokens) nativeEmail(pool *pgxpool.Pool, service *tokenservice.Service) (*tokenservice.NativeEmailLogin, error) {
	login, _, err := p.nativeLogin(pool, service)
	if err != nil {
		return nil, err
	}
	policy := settingsservice.New(settingspostgres.New(pool))
	cfg := p.cfg.Native.EmailOTP
	cfg.CheckPolicy = func(ctx context.Context) error { return policy.CheckPublic(ctx, "emailotp", false) }
	email := otpservice.New(otppostgres.New(pool), p.native.emailCipher, p.native.limits, nil, tokengenerate.New(), cfg)
	return tokenservice.NewNativeEmailLogin(login, email)
}
