package config

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type ProjectDeliveryConfig struct {
	Enabled            bool          `env:"PLATFORM_PROJECT_DELIVERY_ENABLED" env-default:"false"`
	Parallelism        int           `env:"PLATFORM_PROJECT_DELIVERY_PARALLELISM" env-default:"2"`
	PageSize           int           `env:"PLATFORM_PROJECT_DELIVERY_PAGE_SIZE" env-default:"16"`
	Interval           time.Duration `env:"PLATFORM_PROJECT_DELIVERY_INTERVAL" env-default:"5s"`
	FleetConcurrency   int           `env:"PLATFORM_PROJECT_DELIVERY_FLEET_CONCURRENCY" env-default:"8"`
	SMTPAllowedTargets string        `env:"PLATFORM_PROJECT_DELIVERY_SMTP_ALLOWED_TARGETS"`
}

func (c ProjectDeliveryConfig) Targets() []string {
	targets := strings.Split(c.SMTPAllowedTargets, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}
	return targets
}

func (cfg Config) validateProjectDelivery() error {
	c := cfg.Platform.Delivery
	if !c.Enabled {
		return nil
	}
	if !cfg.Platform.Enabled || !cfg.Platform.Runtime.Enabled {
		return errors.New("PLATFORM_PROJECT_DELIVERY_ENABLED requires platform and project runtime")
	}
	if c.Parallelism < 1 || c.Parallelism > projectruntime.StateBatchSize || c.PageSize < c.Parallelism || c.PageSize > projectruntime.StateBatchSize || c.Interval < time.Second || c.Interval > time.Minute {
		return errors.New("invalid project delivery parallelism/page size/interval")
	}
	// Reserve at least half the shared lease slots for HTTP and other consumers.
	if c.Parallelism > cfg.Platform.Runtime.MaxAcquiring/2 || c.Parallelism > cfg.Platform.Runtime.MaxRuntimes {
		return errors.New("project delivery exceeds shared runtime capacity reserve")
	}
	instances := cfg.Platform.Resources.APIInstances
	if instances < 1 || c.FleetConcurrency < 1 || c.Parallelism > c.FleetConcurrency/instances {
		return errors.New("project delivery exceeds declared fleet concurrency including surge")
	}
	return c.ValidateTargets()
}

func (c ProjectDeliveryConfig) ValidateTargets() error {
	targets := c.Targets()
	if len(targets) < 1 || len(targets) > 16 {
		return errors.New("project delivery requires 1..16 SMTP targets")
	}
	for _, target := range targets {
		host, port, err := net.SplitHostPort(target)
		number, parseErr := strconv.Atoi(port)
		candidate := settingsdomain.SMTPConfig{Host: host, Port: number, From: "auth@example.test", Domain: "example.test", RequireTLS: true}
		if err != nil || parseErr != nil || candidate.Validate() != nil {
			return errors.New("invalid project delivery SMTP target")
		}
	}
	return nil
}
