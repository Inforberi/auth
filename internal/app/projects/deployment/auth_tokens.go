package deployment

import (
	"slices"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func compileProjectJWT(cfg *config.Config, entry projectMethodDeployment) (*projectnative.ProjectTokenConfig, error) {
	manifest := entry.JWT
	catalog, err := accesssettings.NewCatalog(manifest.Permissions)
	if err != nil {
		return nil, err
	}
	tokens := &projectnative.ProjectTokenConfig{
		Enabled: true, Catalog: catalog, Timeout: cfg.Platform.HTTP.BuildTimeout,
		Limits: tokenredis.Limits{ActorPerMinute: cfg.JWT.ActorPerMinute, SessionPerMinute: cfg.JWT.SessionPerMinute, IPPerMinute: cfg.JWT.IPPerMinute, ProjectPerMinute: cfg.JWT.ProjectPerMinute},
		Tokens: tokenservice.Config{AccessTTL: cfg.JWT.AccessTTL, Resources: manifest.Resources},
	}
	if manifest.Native {
		tokens.Tokens.Native = &tokenservice.NativePolicy{IdleTTL: cfg.JWT.RefreshIdleTTL, AbsoluteTTL: cfg.JWT.RefreshAbsoluteTTL, Sessions: cfg.Session}
		tokens.Native = projectnative.ProjectNativeConfig{PasswordEnabled: manifest.Password, Capacity: cfg.Capacity, MFA: cfg.MFA, EmailOTP: cfg.EmailOTP}
		tokens.Native.MFA.RecoveryEnabled = false
		tokens.Native.EmailOTP.CheckPolicy = nil
		tokens.Native.EmailOTP.Enabled, tokens.Native.EmailOTP.ReauthenticationEnabled = entry.EmailOTP, false
	}
	if len(manifest.Clients) > 0 {
		if err := tokenservice.ValidateIntrospectionClients(manifest.Clients, manifest.Resources, catalog); err != nil {
			return nil, err
		}
		tokens.Introspection = &projectnative.ProjectIntrospectionConfig{Clients: manifest.Clients, ConsumerPerMinute: cfg.JWT.IntrospectionConsumerPerMinute, ProjectPerMinute: cfg.JWT.IntrospectionProjectPerMinute}
	}
	if err := tokenservice.ValidateConfiguration(tokens.Tokens, catalog); err != nil {
		return nil, err
	}
	return tokens, nil
}

func cloneProjectTokenConfig(source projectnative.ProjectTokenConfig) projectnative.ProjectTokenConfig {
	result := source
	result.Tokens.Resources = slices.Clone(source.Tokens.Resources)
	for i := range result.Tokens.Resources {
		result.Tokens.Resources[i].Permissions = slices.Clone(source.Tokens.Resources[i].Permissions)
	}
	if source.Tokens.Native != nil {
		native := *source.Tokens.Native
		result.Tokens.Native = &native
	}
	if source.Introspection != nil {
		inspection := *source.Introspection
		inspection.Clients = slices.Clone(source.Introspection.Clients)
		for i := range inspection.Clients {
			inspection.Clients[i].SecretHashes = slices.Clone(source.Introspection.Clients[i].SecretHashes)
			inspection.Clients[i].Audiences = slices.Clone(source.Introspection.Clients[i].Audiences)
		}
		result.Introspection = &inspection
	}
	return result
}
