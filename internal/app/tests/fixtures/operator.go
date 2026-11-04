package fixtures

import (
	"time"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/admission"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accountsetup "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func OperatorConfig(realm string) *config.Config {
	setupSecret, err := tokengenerate.New().GenerateToken()
	if err != nil {
		panic(err)
	}
	cfg := &config.Config{
		Platform:     config.PlatformConfig{Enabled: true, RealmID: realm, Origin: "https://console.auth.example", ProjectAuthDomain: "auth.example", StorageTarget: "primary", Operations: admission.DefaultConfig(), Resources: config.DefaultPlatformResources()},
		HTTP:         requestmiddleware.CapacityConfig{MaxInFlight: 16, RequestTimeout: 10 * time.Second},
		Browser:      requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://console.auth.example"}},
		Account:      accountservice.Config{URL: "https://console.auth.example/verify", EncryptionKey: "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100},
		InitialSetup: accountsetup.SetupConfig{Enabled: true, Secret: setupSecret},
		MFA:          mfaservice.Config{Enabled: true, Issuer: "Operator", ChallengeTTL: 5 * time.Minute, UserLimitPerMinute: 30, IPLimitPerMinute: 50, GlobalLimitPerMinute: 100},
		Session:      sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute},
		Password:     passwordrecovery.Config{ResetTokenTTL: 30 * time.Minute, ResetURL: "https://console.auth.example/reset", ResetGlobalLimit: 100},
		Capacity:     passwordservice.CapacityConfig{HashConcurrency: 1, LoginIPLimit: 30, LoginEmailLimit: 30, LoginGlobalLimit: 100},
		Retention:    accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 100, Interval: time.Minute},
	}
	cfg.Postgres.MaxConns = 6
	cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "test TLS", "test TLS"
	return cfg
}
