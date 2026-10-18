package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func (s realmSecurity) assembleProviderSettings(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, policy settingsdomain.Policy) (*settingsservice.Providers, error) {
	google, err := s.cipher(cfg.Account.EncryptionKey, "provider-google:v1")
	if err != nil {
		return nil, err
	}
	telegram, err := s.cipher(cfg.Account.EncryptionKey, "provider-telegram:v1")
	if err != nil {
		return nil, err
	}
	svc := settingsservice.NewProviders(settingspostgres.New(pool), google, telegram)
	for _, seed := range []struct {
		name, id, secret string
		enabled          bool
	}{
		{"google", cfg.Google.ClientID, cfg.Google.ClientSecret, policy.Methods.Google},
		{"telegram", cfg.Telegram.ClientID, cfg.Telegram.ClientSecret, policy.Methods.Telegram},
	} {
		if err := svc.Initialize(ctx, seed.name, seed.id, seed.secret, seed.enabled); err != nil {
			return nil, err
		}
		stored, _, err := svc.Credentials(ctx, seed.name)
		if err != nil {
			return nil, err
		}
		if seed.enabled && (!stored.SecretSet || stored.ClientID == "") {
			return nil, settingsdomain.ErrMethodNotReady
		}
	}
	return svc, nil
}
