package runtime

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsredis "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/redis"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type ProjectSMTPDependencies struct {
	Registry *projectruntime.Registry
	Reader   *runtimepostgres.RuntimeCredentialReader
	Redis    *redis.Client
}

type SMTP struct {
	key      projectruntime.Key
	registry *projectruntime.Registry
	reader   *runtimepostgres.RuntimeCredentialReader
	cipher   settingssmtp.SMTPCipher
	limits   settingsservice.SettingsLimiter
	allowed  []string
}

// NewProjectMailer requires saved project SMTP settings; it never seeds missing settings.
func NewProjectMailer(ctx context.Context, key projectruntime.Key, allowed []string, deps ProjectSMTPDependencies) (*mailer.Mailer, error) {
	if deps.Registry == nil || deps.Reader == nil || deps.Redis == nil {
		return nil, errors.New("incomplete project SMTP dependencies")
	}
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	if err != nil {
		return nil, err
	}
	source, err := NewSMTP(key, configuration.EncryptionKey(), allowed, deps)
	if err != nil {
		return nil, err
	}
	if _, err := source.Credentials(ctx); err != nil {
		return nil, err
	}
	return mailer.NewWithSource(source.Credentials), nil
}

func NewSMTP(key projectruntime.Key, root string, allowed []string, deps ProjectSMTPDependencies) (*SMTP, error) {
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	if err != nil {
		return nil, err
	}
	cipher, err := secretbox.ForScope(scope, root, "smtp-settings:v1")
	if err != nil {
		return nil, err
	}
	limits, err := settingsredis.NewSMTPScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	return &SMTP{
		key: key, registry: deps.Registry, reader: deps.Reader,
		cipher: cipher, limits: limits, allowed: slices.Clone(allowed),
	}, nil
}

func (s *SMTP) Credentials(ctx context.Context) (mailer.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var result mailer.Config
	err := s.registry.UsePool(ctx, s.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		var err error
		result, err = s.CredentialsInPool(ctx, pool)
		return err
	})
	if err != nil {
		return mailer.Config{}, err
	}
	// Only configuration leaves the lease; SMTP I/O never retains a project pool or connection.
	return result, nil
}

func (s *SMTP) CredentialsInPool(ctx context.Context, pool *pgxpool.Pool) (mailer.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.RequireCurrent(ctx); err != nil {
		return mailer.Config{}, err
	}
	svc, err := settingssmtp.NewSMTP(settingspostgres.New(pool), s.cipher,
		func(ctx context.Context, c settingsdomain.SMTPConfig, password string) error {
			return mailer.CheckContext(ctx, MailConfig(c, password))
		}, s.limits, s.allowed, true)
	if err != nil {
		return mailer.Config{}, err
	}
	c, password, err := svc.Credentials(ctx)
	if err != nil {
		return mailer.Config{}, err
	}
	if err := s.RequireCurrent(ctx); err != nil {
		return mailer.Config{}, err
	}
	return MailConfig(c, password), nil
}

func (s *SMTP) RequireCurrent(ctx context.Context) error {
	current, err := s.reader.CurrentRuntimes(ctx, []projectruntime.Key{s.key})
	if err != nil {
		return err
	}
	if !current[0] {
		return projectdomain.ErrConflict
	}
	return nil
}

func (s *SMTP) Use(ctx context.Context, operation func(context.Context, *pgxpool.Pool, *mailer.Mailer) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.registry.UsePool(ctx, s.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := s.RequireCurrent(ctx); err != nil {
			return err
		}
		// The source uses this lease, not another registry acquisition. No service escapes it.
		mail := mailer.NewWithSource(func(ctx context.Context) (mailer.Config, error) { return s.CredentialsInPool(ctx, pool) })
		if err := operation(ctx, pool, mail); err != nil {
			return err
		}
		return s.RequireCurrent(ctx)
	})
}
