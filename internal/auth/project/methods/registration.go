package methods

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	registrationapp "github.com/Inforberi/financial-intelligence/internal/auth/account/registration"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type ProjectRegistrationVerification struct {
	Origin string
	Config accountservice.Config
}

type projectRegistration struct {
	cfg        accountservice.Config
	configured bool
	origin     string
	cipher     accountservice.Cipher
	limits     accountservice.Limiter
}

func newProjectRegistration(scope realmscope.Scope, root string, cfg *ProjectRegistrationVerification, rdb *redis.Client) (*projectRegistration, error) {
	cipher, err := secretbox.ForScope(scope, root, "email-verification:v1")
	if err != nil {
		return nil, err
	}
	limits, err := accountredis.NewScoped(rdb, scope)
	if err != nil {
		return nil, err
	}
	registration := &projectRegistration{cipher: cipher, limits: limits}
	if cfg != nil {
		verification := cfg.Config
		verification.EncryptionKey = root
		if err := verification.Validate(true); err != nil {
			return nil, err
		}
		if err := projectbinding.ValidateProjectEmailOrigin(cfg.Origin, verification.URL); err != nil {
			return nil, err
		}
		verification.EncryptionKey = ""
		registration.cfg, registration.configured = verification, true
		registration.origin = cfg.Origin
	}
	return registration, nil
}

func (r *projectRegistration) account(pool *pgxpool.Pool) (*accountemail.Verification, *accountpostgres.Repository) {
	repo := accountpostgres.New(pool)
	// Registration only prepares encrypted mail; SMTP belongs to the outbox worker.
	return accountemail.NewVerification(repo, r.limits, r.cipher, nil, r.cfg), repo
}

func (p *ProjectPassword) Register(ctx context.Context, email, password, userAgent, ip string) (*passwordservice.RegisterResult, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	var result *passwordservice.RegisterResult
	err := p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.requireCurrent(ctx); err != nil {
			return err
		}
		verifier, account := p.registration.account(pool)
		if err := verifier.AllowRegistration(ctx, ip); err != nil {
			return err
		}
		var repo *passwordpostgres.PasswordRepo
		if p.registration.configured {
			cfg := p.registration.cfg
			base := settings.LinkLifetimePolicy{VerificationSeconds: int64(cfg.TTL / time.Second)}
			repo = registrationapp.Assemble(pool, verifier, account, func(ctx context.Context, tx pgx.Tx) (time.Duration, error) {
				policy, err := settingspg.ProjectLinkLifetime(ctx, tx, base, int64(cfg.ResendInterval/time.Second))
				return time.Duration(policy.VerificationSeconds) * time.Second, err
			}, func(ctx context.Context, tx pgx.Tx) (string, error) {
				policy, err := settingspg.ProjectFrontend(ctx, tx, settings.FrontendPolicy{VerificationURL: cfg.URL})
				if err != nil {
					return "", err
				}
				if err := (settings.FrontendPolicy{
					Origins: p.registration.origin, VerificationURL: policy.VerificationURL, ResetURL: cfg.URL,
				}).Validate([]string{p.registration.origin}); err != nil {
					return "", err
				}
				return policy.VerificationURL, nil
			})
		} else {
			// SQL calls this only for optional/required verification, then rolls back all account writes.
			repo = passwordpostgres.NewWithRegistration(pool, func(context.Context, pgx.Tx, accountdomain.UserID, accountdomain.AddressID, string) error {
				return projectdomain.ErrUnavailable
			})
		}
		passwords, err := p.passwordService(pool, repo)
		if err != nil {
			return err
		}
		result, err = passwords.Register(ctx, email, password, userAgent, ip)
		if err != nil {
			return err
		}
		return p.requireCurrent(ctx)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
