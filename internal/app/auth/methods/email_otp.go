package methods

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type EmailOTP struct {
	Policy   *settingshttp.EmailOTPPolicyHandler
	Service  *otpservice.Service
	Handler  *otphttp.Handler
	Delivery *otpservice.Delivery
}

func AssembleEmailOTP(ctx context.Context, scope realmscope.Scope, pool *pgxpool.Pool, redis *redis.Client, mail *mailer.Mailer, sessions *sessionservice.Login, tokens *tokengenerate.TokenManager, cfg *config.Config, log *zap.Logger) (*EmailOTP, error) {
	if !cfg.EmailOTP.Enabled && !cfg.EmailOTP.ReauthenticationEnabled {
		return &EmailOTP{}, nil
	}
	cipher, err := secretbox.ForScope(scope, cfg.Account.EncryptionKey, "email-login:v1")
	if err != nil {
		return nil, err
	}
	repo := otppostgres.New(pool)
	limits, err := passwordredis.NewScoped(redis, scope)
	if err != nil {
		return nil, err
	}
	settings := cfg.EmailOTP
	policy, err := assembleEmailOTPPolicy(ctx, settingspostgres.New(pool), &settings, cfg.SettingsSource.Mode, log)
	if err != nil {
		return nil, err
	}
	service := otpservice.New(repo, cipher, limits, sessions, tokens, settings)
	return &EmailOTP{Policy: policy, Service: service, Handler: otphttp.New(service, log), Delivery: otpservice.NewDelivery(repo, cipher, mail)}, nil
}
