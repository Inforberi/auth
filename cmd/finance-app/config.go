package main

import (
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Postgres postgres.Config
}

func newConfig() (*Config, error) {
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	return &cfg, nil
}
