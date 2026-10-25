package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaredis "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/redis"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type projectMFALogin struct {
	cipher *secretbox.Cipher
	limits *mfaredis.Limiter
	config mfaservice.LoginConfig
}

func newProjectMFALogin(scope realmscope.Scope, root string, cfg ProjectPasswordConfig, deps ProjectPasswordDependencies) (*projectMFALogin, error) {
	if !cfg.MFA.Enabled {
		return nil, nil
	}
	cipher, err := (realmSecurity{scope: scope}).cipher(root, "mfa:v1")
	if err != nil {
		return nil, err
	}
	limits, err := mfaredis.NewScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	return &projectMFALogin{cipher: cipher, limits: limits, config: mfaservice.LoginConfig{
		Issuer: cfg.MFA.Issuer, AllowPrimary: func(method, issuer string) bool { return method == "password" && issuer == "" },
		ChallengeTTL: cfg.MFA.ChallengeTTL, SessionTTL: cfg.Session.SessionTTL, AbsoluteSessionTTL: cfg.Session.AbsoluteSessionTTL,
		AdminIdleTimeout: cfg.Session.AdminIdleTimeout, AdminAbsoluteTTL: cfg.Session.AdminAbsoluteTTL, AdminActivityInterval: cfg.Session.AdminActivityInterval,
		UserLimitPerMinute: cfg.MFA.UserLimitPerMinute, IPLimitPerMinute: cfg.MFA.IPLimitPerMinute, GlobalLimitPerMinute: cfg.MFA.GlobalLimitPerMinute,
	}}, nil
}

func (m *projectMFALogin) newLogin(pool *pgxpool.Pool) (*mfaservice.Login, error) {
	return mfaservice.NewLogin(mfapostgres.New(pool), m.cipher, mfatotp.Authenticator{}, m.limits, tokengenerate.New(), m.config)
}
