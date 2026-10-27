package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type ProjectProfileConfig struct {
	BrowserEnabled       bool
	UserDirectoryEnabled bool
	Password             *ProjectPasswordConfig
	EmailOTP             *ProjectEmailOTPConfig
	Google, Telegram     *ProjectOIDCConfig
	Verification         *accountservice.Config
	Recovery             *passwordservice.Config
	EmailManagement      *ProjectEmailConfig
	Tokens               *ProjectTokenConfig
	Timeout              time.Duration
}

type ProjectProfileDependencies struct {
	ProjectTokenDependencies
	OIDCClients *ProjectOIDCClients
	Delivery    *ProjectDelivery
}

type ProjectProfile struct {
	key                      projectruntime.Key
	origin                   string
	policy                   settingsdomain.Snapshot
	deps                     ProjectProfileDependencies
	states                   map[string]ProjectFeatureState
	observedAt               time.Time
	password                 *ProjectPassword
	emailOTP                 *ProjectEmailOTP
	google, telegram         *ProjectOIDC
	verification, recovery   *ProjectEmail
	binding, change          *ProjectEmail
	provisioning, activation *ProjectEmail
	bindingConfirmation      *ProjectEmail
	changeProtection         *ProjectEmail
	tokens                   *ProjectTokens
	mfa                      *projectMFA
	mfaManagement            *projectMFA
	userDirectory            *projectUserDirectory
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
	p.buildProfileEmailManagement(ctx, cfg, redisReady)
	p.finishProfileRegistration(cfg)
	p.buildProfileProvisioning(ctx, cfg, redisReady)
	p.buildProfileUserDirectory(cfg)
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
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
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
		for _, view := range configuredBrowserPolicies(cfg) {
			if view.mfa.Enabled {
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
