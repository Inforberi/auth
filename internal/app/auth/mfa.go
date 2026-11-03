package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	mfadelivery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/delivery/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaloginhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfamanagementhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	mfarecovery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/service"
	mfarecoveryhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/transport/http"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaredis "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/redis"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type mfaApp struct {
	sessions        *sessionservice.Login
	login           *mfalogin.Login
	handler         *mfamanagementhttp.Handler
	loginHandler    *mfaloginhttp.Handler
	recoveryHandler *mfarecoveryhttp.Handler
	delivery        *mfadelivery.SecurityDelivery
}

func (s realmSecurity) assembleMFA(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, sessions *sessionservice.SessionService, tokens *tokengenerate.TokenManager, mail mfadelivery.SecurityMailer, cfg *config.Config, log *zap.Logger) (*mfaApp, error) {
	repo := mfapostgres.NewWithEmailProof(pool, cfg.EmailOTP.ReauthenticationEnabled)
	if cfg.Platform.Enabled {
		repo = mfapostgres.NewPlatform(pool)
	}
	cipher, err := s.cipher(cfg.Account.EncryptionKey, "mfa:v1")
	if err != nil {
		return nil, err
	}
	worker, err := mfadelivery.NewSecurityDelivery(repo, cipher, mail)
	if err != nil {
		return nil, err
	}
	// Delivery drains committed events independently of allowing new recovery operations.
	if !cfg.MFA.Enabled {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := repo.CheckDisabled(checkCtx); err != nil {
			return nil, err
		}
		return &mfaApp{sessions: sessionservice.NewLogin(sessions, nil), delivery: worker}, nil
	}
	if cfg.MFA.RecoveryEnabled {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		check := repo.CheckRecoveryOperator
		if cfg.Platform.Enabled {
			check = repo.CheckPlatformRecoveryOperator
		}
		err := check(checkCtx)
		cancel()
		if err != nil {
			return nil, err
		}
	}
	limits, err := mfaredis.NewScoped(rdb, s.scope)
	if err != nil {
		return nil, err
	}
	management, err := mfamanagement.NewConfigured(repo, cipher, totp.Authenticator{}, limits, tokens, cfg.MFA)
	if err != nil {
		return nil, err
	}
	allowPrimary := mfaPrimaryPolicy(cfg)
	login, err := mfalogin.NewLogin(repo, cipher, totp.Authenticator{}, limits, tokens, mfaservice.LoginConfig{
		Issuer:       cfg.MFA.Issuer,
		AllowPrimary: allowPrimary,
		ChallengeTTL: cfg.MFA.ChallengeTTL, SessionTTL: cfg.Session.SessionTTL, AbsoluteSessionTTL: cfg.Session.AbsoluteSessionTTL,
		AdminIdleTimeout: cfg.Session.AdminIdleTimeout, AdminAbsoluteTTL: cfg.Session.AdminAbsoluteTTL, AdminActivityInterval: cfg.Session.AdminActivityInterval,
		UserLimitPerMinute: cfg.MFA.UserLimitPerMinute, IPLimitPerMinute: cfg.MFA.IPLimitPerMinute, GlobalLimitPerMinute: cfg.MFA.GlobalLimitPerMinute,
	})
	if err != nil {
		return nil, err
	}
	recovery, err := mfarecovery.NewRecovery(repo, cipher, totp.Authenticator{}, limits, cfg.MFA, allowPrimary)
	if err != nil {
		return nil, err
	}
	return &mfaApp{sessions: sessionservice.NewLogin(sessions, login), login: login, handler: mfamanagementhttp.New(management, log), loginHandler: mfaloginhttp.New(login, log), recoveryHandler: mfarecoveryhttp.New(recovery, log), delivery: worker}, nil
}

func mfaPrimaryPolicy(cfg *config.Config) func(string, string) bool {
	return func(method, issuer string) bool {
		switch method {
		case "password":
			return true
		case "emailotp":
			return cfg.EmailOTP.Enabled
		case "oidc":
			return cfg.Telegram.Enabled && issuer == cfg.Telegram.FlowConfig().Issuer || cfg.Google.Enabled && issuer == cfg.Google.FlowConfig().Issuer
		default:
			return false
		}
	}
}
