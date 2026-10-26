package auth

import (
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaredis "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/redis"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type projectMFALogin struct {
	cipher           *secretbox.Cipher
	limits           *mfaredis.Limiter
	config           mfaservice.LoginConfig
	managementConfig mfaservice.Config
}

func newProjectMFALogin(scope realmscope.Scope, root string, cfg mfaservice.Config, session sessionservice.Config, rdb *redis.Client, primary string) (*projectMFALogin, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if primary != "password" && primary != "emailotp" && !settingsdomain.ValidProvider(primary) {
		return nil, errors.New("unsupported project MFA primary")
	}
	cipher, err := (realmSecurity{scope: scope}).cipher(root, "mfa:v1")
	if err != nil {
		return nil, err
	}
	limits, err := mfaredis.NewScoped(rdb, scope)
	if err != nil {
		return nil, err
	}
	return &projectMFALogin{cipher: cipher, limits: limits, managementConfig: cfg, config: mfaservice.LoginConfig{
		Issuer: cfg.Issuer, AllowPrimary: func(method, issuer string) bool { return settingsdomain.PrimaryMethod(method, issuer) == primary },
		ChallengeTTL: cfg.ChallengeTTL, SessionTTL: session.SessionTTL, AbsoluteSessionTTL: session.AbsoluteSessionTTL,
		AdminIdleTimeout: session.AdminIdleTimeout, AdminAbsoluteTTL: session.AdminAbsoluteTTL, AdminActivityInterval: session.AdminActivityInterval,
		UserLimitPerMinute: cfg.UserLimitPerMinute, IPLimitPerMinute: cfg.IPLimitPerMinute, GlobalLimitPerMinute: cfg.GlobalLimitPerMinute,
	}}, nil
}

func (m *projectMFALogin) newLogin(pool *pgxpool.Pool) (*mfaservice.Login, error) {
	return mfaservice.NewLogin(mfapostgres.New(pool), m.cipher, mfatotp.Authenticator{}, m.limits, tokengenerate.New(), m.config)
}

func validateProjectMFA(cfg mfaservice.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.RecoveryEnabled {
		return errors.New("project loss-all-factors recovery is not assembled")
	}
	return nil
}
