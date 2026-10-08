package config

import (
	"github.com/ilyakaznacheev/cleanenv"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func readSession(cfg *sessionservice.Config) error { return cleanenv.ReadEnv(cfg) }
