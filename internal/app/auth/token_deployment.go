package auth

import (
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
)

// Called only after token assembly succeeds; readiness is local, not fleet-wide.
func tokenDeployment(cfg settings.Config, resources []service.Resource, native, introspection bool) settingsdomain.TokenDeployment {
	if !cfg.Enabled {
		return settingsdomain.TokenDeployment{}
	}
	result := settingsdomain.TokenDeployment{Enabled: true, NativeEnabled: native, IntrospectionEnabled: introspection, Issuer: cfg.Issuer, AccessTTLSeconds: int64(cfg.AccessTTL.Seconds())}
	for _, resource := range resources {
		permissions := make([]string, len(resource.Permissions))
		for i, key := range resource.Permissions {
			permissions[i] = string(key)
		}
		result.Resources = append(result.Resources, settingsdomain.TokenResource{Audience: resource.Audience, Mode: resource.EffectiveMode(), Permissions: permissions})
	}
	return result
}
