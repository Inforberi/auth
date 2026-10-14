package config

import (
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	googleservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	telegramservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
	"github.com/Inforberi/financial-intelligence/internal/server/http"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type Config struct {
	Access            accesssettings.Config
	Browser           requestmiddleware.OriginConfig
	HTTP              requestmiddleware.CapacityConfig
	Proxy             requestmiddleware.ProxyConfig
	Account           accountservice.Config
	EmailChange       accountservice.EmailChangeConfig
	EmailBinding      accountservice.EmailBindingConfig
	Invitation        accountservice.InvitationConfig
	TemporaryPassword passwordservice.TemporaryPasswordConfig
	EmailOTP          otpservice.Config
	Telegram          telegramservice.Config
	Google            googleservice.Config
	Retention         accountservice.RetentionConfig
	Postgres          postgres.Config
	Logger            logger.Config
	Session           sessionservice.Config
	MFA               mfaservice.Config
	Server            httpserver.Config
	Redis             redisclient.Config
	MailSender        mailer.Config
	Password          passwordservice.Config
	Capacity          passwordservice.CapacityConfig
	Swagger           SwaggerConfig
}

func New() (*Config, error) {
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, fmt.Errorf("failed to read configuration (check required variables and types)")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

type SwaggerConfig struct {
	Enabled  bool   `env:"SWAGGER_ENABLED" env-default:"false"`
	Username string `env:"SWAGGER_USERNAME"`
	Password string `env:"SWAGGER_PASSWORD"`
}
