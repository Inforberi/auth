package auth

import (
	"context"
	"errors"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type ProjectEmailConfig struct {
	Origin       string
	Verification accountservice.Config
	Password     passwordservice.Config
}

type ProjectEmailDependencies struct {
	ProjectSMTPDependencies
	Hash *hasher.Bounded
}

type ProjectEmail struct {
	runtime *projectEmailRuntime
	cfg     ProjectEmailConfig
	hash    *hasher.Bounded
}

func NewProjectEmail(ctx context.Context, key projectruntime.Key, cfg ProjectEmailConfig, allowed []string, deps ProjectEmailDependencies) (*ProjectEmail, error) {
	if deps.Registry == nil || deps.Reader == nil || deps.Redis == nil || deps.Hash == nil {
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
	runtime, err := newProjectEmailRuntime(key, configuration.EncryptionKey(), allowed, deps.ProjectSMTPDependencies)
	if err != nil {
		return nil, err
	}
	if _, err := runtime.smtp.credentials(ctx); err != nil {
		return nil, err
	}
	return &ProjectEmail{runtime: runtime, cfg: cfg, hash: deps.Hash}, nil
}

func (c ProjectEmailConfig) validate() error {
	if err := c.Verification.Validate(true); err != nil {
		return err
	}
	if err := c.Password.Validate(); err != nil {
		return err
	}
	return validateProjectEmailOrigin(c.Origin, c.Verification.URL, c.Password.ResetURL)
}

func validateProjectEmailOrigin(originURL string, urls ...string) error {
	origin, err := url.Parse(originURL)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("project email requires a trusted HTTPS origin")
	}
	for _, raw := range urls {
		target, err := url.Parse(raw)
		if err != nil || target.Scheme != origin.Scheme || target.Host != origin.Host {
			return errors.New("project email URL must use its trusted origin")
		}
	}
	return nil
}

func (p *ProjectEmail) ResendVerification(ctx context.Context, email, ip string) error {
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.verification(pool, mail, p.cfg.Verification).Resend(ctx, email, ip)
	})
}

func (p *ProjectEmail) ConfirmVerification(ctx context.Context, token, ip string) error {
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.verification(pool, mail, p.cfg.Verification).Confirm(ctx, token, ip)
	})
}

func (p *ProjectEmail) ForgotPassword(ctx context.Context, email, ip string) error {
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.recovery(pool, mail, p.hash, p.cfg.Password).Forgot(ctx, email, ip)
	})
}

func (p *ProjectEmail) ResetPassword(ctx context.Context, token, password, confirmation, ip string) error {
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		return p.runtime.recovery(pool, mail, p.hash, p.cfg.Password).Reset(ctx, token, password, confirmation, ip)
	})
}
