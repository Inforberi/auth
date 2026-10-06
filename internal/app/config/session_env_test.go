package config

import (
	"github.com/ilyakaznacheev/cleanenv"

	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func readSession(cfg *sessionmodel.Config) error { return cleanenv.ReadEnv(cfg) }
