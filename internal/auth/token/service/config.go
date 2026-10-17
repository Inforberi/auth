package service

import (
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type Resource struct {
	Audience    string                       `json:"audience"`
	Mode        string                       `json:"mode"`
	Permissions []accessdomain.PermissionKey `json:"permissions"`
}

type Config struct {
	AccessTTL time.Duration
	Resources []Resource
}

type resourcePolicy struct {
	mode        string
	permissions map[accessdomain.PermissionKey]bool
}

func resourcePolicies(cfg Config, catalog settings.Catalog) (map[string]resourcePolicy, error) {
	if cfg.AccessTTL < time.Second || cfg.AccessTTL > authjwt.MaxLifetime || cfg.AccessTTL%time.Second != 0 || len(cfg.Resources) == 0 || len(cfg.Resources) > 32 {
		return nil, authjwt.ErrConfiguration
	}
	policies := make(map[string]resourcePolicy, len(cfg.Resources))
	core, err := settings.NewCatalog(nil)
	if err != nil {
		return nil, err
	}
	for _, resource := range cfg.Resources {
		mode := resource.Mode
		if mode == "" {
			mode = authjwt.Strict
		}
		if !authjwt.ValidAudience(resource.Audience) || mode != authjwt.Strict && mode != authjwt.Local ||
			len(resource.Permissions) == 0 || len(resource.Permissions) > 256 {
			return nil, authjwt.ErrConfiguration
		}
		if _, duplicate := policies[resource.Audience]; duplicate {
			return nil, authjwt.ErrConfiguration
		}
		allowed := make(map[accessdomain.PermissionKey]bool, len(resource.Permissions))
		for _, key := range resource.Permissions {
			if !catalog.Contains(key) || allowed[key] || mode == authjwt.Local && core.Contains(key) {
				return nil, authjwt.ErrConfiguration
			}
			allowed[key] = true
		}
		policies[resource.Audience] = resourcePolicy{mode: mode, permissions: allowed}
	}
	return policies, nil
}
