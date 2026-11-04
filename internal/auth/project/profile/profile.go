package profile

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	projectaccess "github.com/Inforberi/financial-intelligence/internal/access/project"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (p *ProjectProfile) runtimeBinding() projectbinding.Binding {
	return projectbinding.Binding{Key: p.key, Registry: p.deps.Registry, Reader: p.deps.Reader}
}

type ProjectProfile struct {
	key                      projectruntime.Key
	origin                   string
	policy                   settingsdomain.Snapshot
	deps                     ProjectProfileDependencies
	states                   map[string]ProjectFeatureState
	observedAt               time.Time
	password                 *projectmethods.ProjectPassword
	emailOTP                 *projectmethods.ProjectEmailOTP
	google, telegram         *projectmethods.ProjectOIDC
	verification, recovery   *projectaccount.ProjectEmail
	binding, change          *projectaccount.ProjectEmail
	provisioning, activation *projectaccount.ProjectEmail
	bindingConfirmation      *projectaccount.ProjectEmail
	changeProtection         *projectaccount.ProjectEmail
	tokens                   *projectnative.ProjectTokens
	mfa                      *projectmfa.ProjectMFA
	mfaManagement            *projectmfa.ProjectMFA
	mfaRecovery              *projectmfa.ProjectMFARecovery
	emailMFA                 *projectmfa.ProjectEmailMFA
	telegramMFA              *projectmfa.ProjectTelegramMFA
	userDirectory            *projectaccount.ProjectUserDirectory
	userLifecycle            *projectaccount.ProjectUserLifecycle
	access                   *projectaccess.ProjectAccess
	authSettings             *projectsettings.ProjectAuthSettings
	smtpSettings             *projectsettings.ProjectSMTPSettings
	providerSettings         *projectsettings.ProjectProviderSettings
	retentionSettings        *projectsettings.ProjectRetentionSettings
	mfaSettings              *projectsettings.ProjectMFASettings
}

func BuildProjectProfile(ctx context.Context, key projectruntime.Key, origin string, cfg ProjectProfileConfig, deps ProjectProfileDependencies) (*ProjectProfile, error) {
	return buildProjectProfile(ctx, key, origin, cfg, deps, false)
}

func buildProjectProfile(ctx context.Context, key projectruntime.Key, origin string, cfg ProjectProfileConfig, deps ProjectProfileDependencies, assess bool) (*ProjectProfile, error) {
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
	p := &ProjectProfile{key: key, origin: origin, policy: configuration.Policy(), deps: deps, states: make(map[string]ProjectFeatureState)}
	observed := p.policy
	if assess {
		p.selectAssessmentPolicy(cfg)
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
	if err := p.checkSnapshotCurrent(ctx, observed); err != nil {
		return nil, err
	}
	p.observedAt = time.Now().UTC()
	return p, nil
}

// CheckCurrent rejects a stale route plan; the caller must rebuild it after a conflict.
func (p *ProjectProfile) CheckCurrent(ctx context.Context) error {
	return p.checkSnapshotCurrent(ctx, p.policy)
}

func (p *ProjectProfile) checkSnapshotCurrent(ctx context.Context, observed settingsdomain.Snapshot) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	currentKey, err := p.deps.Reader.ResolveRuntime(ctx, p.origin)
	if err != nil {
		return err
	}
	if currentKey != p.key {
		return projectdomain.ErrConflict
	}
	return p.checkPolicySnapshot(ctx, observed)
}

func (p *ProjectProfile) checkPolicyCurrent(ctx context.Context) error {
	return p.checkPolicySnapshot(ctx, p.policy)
}

func (p *ProjectProfile) checkPolicySnapshot(ctx context.Context, observed settingsdomain.Snapshot) error {
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		current, err := settingspostgres.New(pool).Load(ctx)
		if err != nil {
			return err
		}
		if current != observed {
			return settingsdomain.ErrPolicyConflict
		}
		return projectbinding.RequireCurrent(ctx, p.deps.Reader, p.key)
	})
}

func profileRedisReady(ctx context.Context, client *redis.Client) bool {
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return client.Ping(ctx).Err() == nil
}

func profileNeedsRedis(cfg ProjectProfileConfig, policy settingsdomain.Policy) bool {
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
