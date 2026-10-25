package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsredis "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/redis"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type ProjectSMTPDependencies struct {
	Registry *projectruntime.Registry
	Reader   *projectpostgres.RuntimeCredentialReader
	Redis    *redis.Client
}

type projectSMTP struct {
	key      projectruntime.Key
	registry *projectruntime.Registry
	reader   *projectpostgres.RuntimeCredentialReader
	cipher   settingsservice.SMTPCipher
	limits   settingsservice.SMTPLimiter
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
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	if err != nil {
		return nil, err
	}
	cipher, err := (realmSecurity{scope: scope}).cipher(configuration.EncryptionKey(), "smtp-settings:v1")
	if err != nil {
		return nil, err
	}
	limits, err := settingsredis.NewSMTPScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	source := &projectSMTP{
		key: key, registry: deps.Registry, reader: deps.Reader,
		cipher: cipher, limits: limits, allowed: slices.Clone(allowed),
	}
	if _, err := source.credentials(ctx); err != nil {
		return nil, err
	}
	return mailer.NewWithSource(source.credentials), nil
}

func (s *projectSMTP) credentials(ctx context.Context) (mailer.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var result mailer.Config
	err := s.registry.UsePool(ctx, s.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := s.requireCurrent(ctx); err != nil {
			return err
		}
		svc, err := settingsservice.NewSMTP(settingspostgres.New(pool), s.cipher,
			func(ctx context.Context, c settingsdomain.SMTPConfig, password string) error {
				return mailer.CheckContext(ctx, smtpMailerConfig(c, password))
			}, s.limits, s.allowed, true)
		if err != nil {
			return err
		}
		c, password, err := svc.Credentials(ctx)
		if err != nil {
			return err
		}
		if err := s.requireCurrent(ctx); err != nil {
			return err
		}
		result = smtpMailerConfig(c, password)
		return nil
	})
	if err != nil {
		return mailer.Config{}, err
	}
	// Only configuration leaves the lease; SMTP I/O never retains a project pool or connection.
	return result, nil
}

func (s *projectSMTP) requireCurrent(ctx context.Context) error {
	current, err := s.reader.CurrentRuntimes(ctx, []projectruntime.Key{s.key})
	if err != nil {
		return err
	}
	if !current[0] {
		return projectdomain.ErrConflict
	}
	return nil
}
