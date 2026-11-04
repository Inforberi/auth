package methods

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	settingsproviders "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (p *ProjectPassword) BrowserPolicy() BrowserPolicy {
	return BrowserPolicy{"password", p.cfg.Session, p.cfg.MFA}
}

func (p *ProjectEmailOTP) BrowserPolicy() BrowserPolicy {
	return BrowserPolicy{"emailotp", p.cfg.Session, p.cfg.MFA}
}

func (p *ProjectOIDC) BrowserPolicy() BrowserPolicy {
	return BrowserPolicy{p.cfg.Provider, p.cfg.Session, p.cfg.MFA}
}

func (p *ProjectPassword) ChangePasswordHandler(log *zap.Logger) http.HandlerFunc {
	return passwordhttp.NewChangePassword(p, p.limits, log).ChangePassword
}

func (p *ProjectOIDC) CheckStoredCredentials(ctx context.Context) error {
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		providers := settingsproviders.NewProviders(settingspostgres.New(pool), p.googleCipher, p.telegramCipher)
		_, _, err := projectProviderCredentials(ctx, providers, p.cfg.Provider)
		return err
	})
}
