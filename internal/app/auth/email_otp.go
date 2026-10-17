package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type emailOTPApp struct {
	service  *otpservice.Service
	handler  *otphttp.Handler
	delivery *otpservice.Delivery
}

func assembleEmailOTP(pool *pgxpool.Pool, redis *redis.Client, mail *mailer.Mailer, sessions *sessionservice.Login, tokens *tokengenerate.TokenManager, cfg *config.Config, log *zap.Logger) (*emailOTPApp, error) {
	if !cfg.EmailOTP.Enabled && !cfg.EmailOTP.ReauthenticationEnabled {
		return &emailOTPApp{}, nil
	}
	cipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "email-login:v1")
	if err != nil {
		return nil, err
	}
	repo := otppostgres.New(pool)
	service := otpservice.New(repo, cipher, passwordredis.New(redis), sessions, tokens, cfg.EmailOTP)
	return &emailOTPApp{service: service, handler: otphttp.New(service, log), delivery: otpservice.NewDelivery(repo, cipher, mail)}, nil
}
