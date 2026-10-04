package config

import "github.com/ilyakaznacheev/cleanenv"

func readSession(cfg *SessionConfig) error { return cleanenv.ReadEnv(cfg) }
