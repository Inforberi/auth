package config

import (
	"errors"
	"time"
)

type ProjectHTTPConfig struct {
	EmailMFA     ProjectEmailMFAConfig
	ManifestFile string        `env:"PLATFORM_PROJECT_AUTH_CONFIG_FILE"`
	Enabled      bool          `env:"PLATFORM_PROJECT_HTTP_ENABLED" env-default:"false"`
	MaxProfiles  int           `env:"PLATFORM_PROJECT_HTTP_MAX_PROFILES" env-default:"8"`
	MaxBuilding  int           `env:"PLATFORM_PROJECT_HTTP_MAX_BUILDING" env-default:"2"`
	BuildTimeout time.Duration `env:"PLATFORM_PROJECT_HTTP_BUILD_TIMEOUT" env-default:"5s"`
	MaxAge       time.Duration `env:"PLATFORM_PROJECT_HTTP_PROFILE_MAX_AGE" env-default:"30s"`
	MaxInFlight  int           `env:"PLATFORM_PROJECT_HTTP_MAX_IN_FLIGHT" env-default:"32"`
}

func (cfg Config) validateProjectHTTP() error {
	c := cfg.Platform.HTTP
	if !c.Enabled {
		return nil
	}
	if !cfg.Platform.Enabled || !cfg.Platform.Runtime.Enabled || cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
		return errors.New("project HTTP requires platform, project runtime and direct TLS")
	}
	if c.MaxProfiles < 1 || c.MaxProfiles > 256 || c.MaxBuilding < 1 || c.MaxBuilding > c.MaxProfiles || c.BuildTimeout <= 0 || c.BuildTimeout > cfg.HTTP.RequestTimeout || c.MaxAge < time.Second || c.MaxAge > 5*time.Minute {
		return errors.New("invalid project HTTP resident/build/age budget")
	}
	if c.MaxInFlight < 1 || c.MaxInFlight > 10000 || c.MaxInFlight > cfg.Platform.Runtime.MaxAcquiring/2 {
		return errors.New("project HTTP admission exceeds runtime capacity reserve")
	}
	return nil
}
