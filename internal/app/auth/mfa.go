package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaredis "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/redis"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func assembleMFA(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, sessions *sessionservice.SessionService, tokens *tokengenerate.TokenManager, mail *mailer.Mailer, cfg *config.Config, log *zap.Logger) (*sessionservice.Login, *mfahttp.Handler, *mfaservice.RecoveryDelivery, error) {
	repo := mfapostgres.NewWithEmailProof(pool, cfg.EmailOTP.ReauthenticationEnabled)
	cipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "mfa:v1")
	if err != nil {
		return nil, nil, nil, err
	}
	worker, err := mfaservice.NewRecoveryDelivery(repo, cipher, mail)
	if err != nil {
		return nil, nil, nil, err
	}
	// Delivery drains committed events independently of allowing new recovery operations.
	if !cfg.MFA.Enabled {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := repo.CheckDisabled(checkCtx); err != nil {
			return nil, nil, nil, err
		}
		return sessionservice.NewLogin(sessions, nil), nil, worker, nil
	}
	if cfg.MFA.RecoveryEnabled {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := repo.CheckRecoveryOperator(checkCtx)
		cancel()
		if err != nil {
			return nil, nil, nil, err
		}
	}
	limits := mfaredis.New(rdb)
	management, err := mfaservice.NewConfigured(repo, cipher, mfatotp.Authenticator{}, limits, tokens, cfg.MFA)
	if err != nil {
		return nil, nil, nil, err
	}
	allowPrimary := mfaPrimaryPolicy(cfg)
	login, err := mfaservice.NewLogin(repo, cipher, mfatotp.Authenticator{}, limits, tokens, mfaservice.LoginConfig{
		AllowPrimary: allowPrimary,
		ChallengeTTL: cfg.MFA.ChallengeTTL, SessionTTL: cfg.Session.SessionTTL, AbsoluteSessionTTL: cfg.Session.AbsoluteSessionTTL,
		UserLimitPerMinute: cfg.MFA.UserLimitPerMinute, IPLimitPerMinute: cfg.MFA.IPLimitPerMinute, GlobalLimitPerMinute: cfg.MFA.GlobalLimitPerMinute,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	recovery, err := mfaservice.NewRecovery(repo, cipher, mfatotp.Authenticator{}, limits, cfg.MFA, allowPrimary)
	if err != nil {
		return nil, nil, nil, err
	}
	return sessionservice.NewLogin(sessions, login), mfahttp.NewWithRecovery(management, login, recovery, log), worker, nil
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
