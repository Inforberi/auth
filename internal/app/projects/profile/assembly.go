package profile

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func BuildProjectProfile(ctx context.Context, key projectruntime.Key, origin string, cfg runtimeprofile.ProjectProfileConfig, deps runtimeprofile.ProjectProfileDependencies) (*runtimeprofile.ProjectProfile, error) {
	return buildProjectProfile(ctx, key, origin, cfg, deps, false)
}

func buildProjectProfile(ctx context.Context, key projectruntime.Key, origin string, cfg runtimeprofile.ProjectProfileConfig, deps runtimeprofile.ProjectProfileDependencies, assess bool) (*runtimeprofile.ProjectProfile, error) {
	if deps.Registry == nil || deps.Reader == nil || cfg.Timeout <= 0 || cfg.Timeout > 30*time.Second {
		return nil, projectdomain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	resolved, err := deps.Reader.ResolveRuntime(ctx, origin)
	if err != nil {
		return nil, err
	}
	if resolved != key {
		return nil, projectdomain.ErrConflict
	}
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	if err != nil {
		return nil, err
	}
	p := &profileAssembly{key: key, origin: origin, policy: configuration.Policy(), deps: deps, states: make(map[string]runtimeprofile.ProjectFeatureState)}
	observed := p.policy
	if assess {
		p.policy.Policy = cfg.AssessmentPolicy(p.policy.Policy)
	}
	redisReady := !profileNeedsRedis(cfg, p.policy.Policy) || profileRedisReady(ctx, deps.Redis)
	p.buildProfileEmail(ctx, cfg, redisReady)
	p.buildProfileMethods(ctx, cfg, redisReady)
	p.buildProfileTokens(ctx, cfg, redisReady)
	p.bindProfileMFA(configuration.EncryptionKey())
	p.buildProfileMFAManagement(cfg, configuration.EncryptionKey(), redisReady)
	p.buildProfileMFARecovery(ctx, cfg, configuration.EncryptionKey(), redisReady)
	p.buildProfileEmailMFA(cfg)
	p.buildProfileTelegramMFA(cfg, configuration.EncryptionKey())
	p.bindFactorSelection()
	p.buildProfileEmailManagement(ctx, cfg, redisReady)
	p.finishProfileRegistration(cfg)
	p.buildProfileProvisioning(ctx, cfg, redisReady)
	p.buildProfileUserDirectory(cfg)
	p.buildProfileUserLifecycle(cfg)
	p.buildProfileAccess(ctx, cfg)
	p.buildProfileAuthSettings(cfg)
	p.buildProfileSMTPSettings(cfg, configuration.EncryptionKey(), redisReady)
	p.buildProfileProviderSettings(cfg, configuration.EncryptionKey())
	p.buildProfileRetentionSettings(cfg)
	p.buildProfileMFASettings(cfg)
	if err := p.checkMFACapability(ctx, cfg); err != nil {
		return nil, err
	}
	assembled := p.runtimeSnapshot()
	if err := assembled.Publish(ctx, observed); err != nil {
		return nil, err
	}
	return assembled, nil
}

func profileRedisReady(ctx context.Context, client *redis.Client) bool {
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return client.Ping(ctx).Err() == nil
}

func profileNeedsRedis(cfg runtimeprofile.ProjectProfileConfig, policy settingsdomain.Policy) bool {
	if cfg.BrowserEnabled {
		if cfg.SMTPSettings != nil {
			return true
		}
		for _, view := range configuredBrowserPolicies(cfg) {
			if view.MFA.Enabled {
				return true
			}
		}
		if cfg.EmailManagement != nil && (cfg.EmailManagement.Binding.Enabled || cfg.EmailManagement.Change.Enabled || cfg.EmailManagement.Invitations.Enabled) {
			return true
		}
		methods := policy.Methods
		if methods.Password || methods.EmailOTP || methods.Google || methods.Telegram {
			return true
		}
		if cfg.EmailOTP != nil && cfg.EmailOTP.OTP.ReauthenticationEnabled {
			return true
		}
	}
	return cfg.Verification != nil || cfg.Recovery != nil || cfg.Tokens != nil && cfg.Tokens.Enabled && cfg.Tokens.Tokens.Native != nil
}
