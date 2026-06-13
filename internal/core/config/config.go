package config

import (
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/infra/httpserver"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/postgres"
	redis_client "github.com/Inforberi/financial-intelligence/internal/core/infra/redis"
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Postgres   postgres.Config
	Logger     logger.Config
	Session    SessionConfig
	Server     httpserver.Config
	Redis      redis_client.Config
	MailSender mailer.Config
}

func New() (*Config, error) {
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	return &cfg, nil
}
