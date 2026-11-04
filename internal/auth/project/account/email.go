package account

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

type ProjectEmailDependencies struct {
	projectbinding.ProjectSMTPDependencies
	Hash *hasher.Bounded
}

type ProjectEmail struct {
	runtime *ProjectEmailRuntime
	cfg     ProjectEmailConfig
	hash    *hasher.Bounded
}

func NewProjectEmail(ctx context.Context, key projectruntime.Key, cfg ProjectEmailConfig, allowed []string, deps ProjectEmailDependencies) (*ProjectEmail, error) {
	return newProjectEmail(ctx, key, cfg, allowed, deps, true)
}

func newProjectEmail(ctx context.Context, key projectruntime.Key, cfg ProjectEmailConfig, allowed []string, deps ProjectEmailDependencies, requireSMTP bool) (*ProjectEmail, error) {
	if deps.Registry == nil || deps.Reader == nil || deps.Redis == nil || deps.Hash == nil && (cfg.RecoveryEnabled || cfg.Invitations.Enabled || cfg.Change.Enabled) {
		return nil, errors.New("incomplete project email dependencies")
	}
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	if err != nil {
		return nil, err
	}
	cfg.Verification.EncryptionKey = configuration.EncryptionKey()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.Verification.EncryptionKey = ""
	runtime, err := NewProjectEmailRuntime(key, configuration.EncryptionKey(), allowed, deps.ProjectSMTPDependencies)
	if err != nil {
		return nil, err
	}
	if requireSMTP {
		if _, err := runtime.smtp.Credentials(ctx); err != nil {
			return nil, err
		}
	}
	return &ProjectEmail{runtime: runtime, cfg: cfg, hash: deps.Hash}, nil
}

func (p *ProjectEmail) ResendVerification(ctx context.Context, email, ip string) error {
	if !p.cfg.VerificationEnabled {
		return projectdomain.ErrUnavailable
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.verification(pool, mail, p.cfg.Verification).Resend(ctx, email, ip)
	})
}

func (p *ProjectEmail) ConfirmVerification(ctx context.Context, token, ip string) error {
	if !p.cfg.VerificationEnabled {
		return projectdomain.ErrUnavailable
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.verification(pool, mail, p.cfg.Verification).Confirm(ctx, token, ip)
	})
}

func (p *ProjectEmail) ForgotPassword(ctx context.Context, email, ip string) error {
	if !p.cfg.RecoveryEnabled {
		return projectdomain.ErrUnavailable
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.recovery(pool, mail, p.hash, p.cfg.Password).Forgot(ctx, email, ip)
	})
}

func (p *ProjectEmail) ResetPassword(ctx context.Context, token, password, confirmation, ip string) error {
	if !p.cfg.RecoveryEnabled {
		return projectdomain.ErrUnavailable
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.recovery(pool, mail, p.hash, p.cfg.Password).Reset(ctx, token, password, confirmation, ip)
	})
}
