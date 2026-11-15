package profile

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func bindProjectCredentialLifetimes(cfg runtimeprofile.ProjectProfileConfig, key projectruntime.Key, deps runtimeprofile.ProjectProfileDependencies) runtimeprofile.ProjectProfileConfig {
	lifetime := func(ctx context.Context) (settings.CredentialLifetimePolicy, error) {
		var result settings.CredentialLifetimePolicy
		err := deps.Registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
			var err error
			result, err = settingspg.ProjectCredentialLifetime(ctx, pool)
			return err
		})
		return result, err
	}
	if cfg.EmailManagement != nil {
		email := *cfg.EmailManagement
		email.Binding.TTLSource = func(ctx context.Context) (time.Duration, error) {
			p, err := lifetime(ctx)
			return durationOrDefault(p.EmailBindingSeconds, email.Binding.TTL), err
		}
		email.Invitations.TTLSource = func(ctx context.Context) (time.Duration, error) {
			p, err := lifetime(ctx)
			return durationOrDefault(p.InvitationSeconds, email.Invitations.TTL), err
		}
		email.Invitations.ReissuePolicySource = func(ctx context.Context) (time.Duration, time.Duration, error) {
			p, err := lifetime(ctx)
			return durationOrDefault(p.InvitationSeconds, email.Invitations.TTL), durationOrDefault(p.InvitationCooldownSeconds, email.Invitations.ReissueCooldown), err
		}
		email.Change.LifetimeSource = func(ctx context.Context) (time.Duration, time.Duration, time.Duration, error) {
			p, err := lifetime(ctx)
			return durationOrDefault(p.EmailChangeSeconds, email.Change.TTL), durationOrDefault(p.EmailChangeRecoverySeconds, email.Change.RecoveryTTL),
				durationOrDefault(p.EmailChangeProtectionSeconds, email.Change.ProtectionTTL), err
		}
		cfg.EmailManagement = &email
	}
	if cfg.Password != nil {
		password := *cfg.Password
		temporary := &password.TemporaryPassword
		temporary.TTLSource = func(ctx context.Context) (time.Duration, error) {
			p, err := lifetime(ctx)
			return durationOrDefault(p.TemporaryPasswordSeconds, temporary.TTL), err
		}
		temporary.SetupTTLSource = func(ctx context.Context) (time.Duration, error) {
			p, err := lifetime(ctx)
			return durationOrDefault(p.TemporarySetupSeconds, temporary.SetupTTL), err
		}
		temporary.ReissuePolicySource = func(ctx context.Context) (time.Duration, time.Duration, error) {
			p, err := lifetime(ctx)
			return durationOrDefault(p.TemporaryPasswordSeconds, temporary.TTL), durationOrDefault(p.TemporaryReissueCooldownSeconds, temporary.ReissueCooldown), err
		}
		cfg.Password = &password
	}
	return cfg
}

func durationOrDefault(seconds int64, fallback time.Duration) time.Duration {
	if seconds == 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}
