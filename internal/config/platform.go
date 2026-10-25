package config

import (
	"fmt"
	"net/url"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/admission"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type PlatformConfig struct {
	Operations        admission.Config
	Resources         PlatformResources
	Runtime           ProjectRuntimeConfig
	Delivery          ProjectDeliveryConfig
	Enabled           bool   `env:"PLATFORM_ENABLED" env-default:"false"`
	RealmID           string `env:"PLATFORM_REALM_ID"`
	Origin            string `env:"PLATFORM_ORIGIN"`
	ProjectAuthDomain string `env:"PLATFORM_PROJECT_AUTH_DOMAIN"`
	StorageTarget     string `env:"PLATFORM_STORAGE_TARGET" env-default:"primary"`
}

func (cfg Config) ValidatePlatform() error {
	if err := cfg.validateProjectDelivery(); err != nil {
		return err
	}
	if !cfg.Platform.Enabled {
		if cfg.Platform.Runtime.Enabled {
			return fmt.Errorf("PLATFORM_PROJECT_RUNTIME_ENABLED requires PLATFORM_ENABLED")
		}
		return nil
	}
	if !operatordomain.RealmID(cfg.Platform.RealmID).Valid() || !projectdomain.ValidOrigin(cfg.Platform.Origin) {
		return fmt.Errorf("platform requires a canonical nonzero PLATFORM_REALM_ID and exact HTTPS PLATFORM_ORIGIN")
	}
	if !cfg.MFA.Enabled {
		return fmt.Errorf("platform requires MFA_ENABLED")
	}
	if !(projectdomain.CreationPolicy{AuthDomain: cfg.Platform.ProjectAuthDomain, StorageTarget: cfg.Platform.StorageTarget, PlatformOrigin: cfg.Platform.Origin}).Valid() {
		return fmt.Errorf("platform requires canonical PLATFORM_PROJECT_AUTH_DOMAIN and a named PLATFORM_STORAGE_TARGET")
	}
	for _, feature := range []struct {
		name    string
		enabled bool
	}{
		{"JWT_ENABLED", cfg.JWT.Enabled},
		{"JWT_NATIVE_ENABLED", cfg.JWT.NativeEnabled},
		{"GOOGLE_LOGIN_ENABLED", cfg.Google.Enabled},
		{"TELEGRAM_LOGIN_ENABLED", cfg.Telegram.Enabled},
		{"EMAIL_OTP_ENABLED", cfg.EmailOTP.Enabled},
		{"EMAIL_REAUTHENTICATION_ENABLED", cfg.EmailOTP.ReauthenticationEnabled},
		{"INVITATIONS_ENABLED", cfg.Invitation.Enabled},
		{"TEMPORARY_PASSWORD_ENABLED", cfg.TemporaryPassword.Enabled},
		{"EMAIL_BINDING_ENABLED", cfg.EmailBinding.Enabled},
		{"EMAIL_CHANGE_ENABLED", cfg.EmailChange.Enabled},
	} {
		if feature.enabled {
			return fmt.Errorf("platform profile does not support %s", feature.name)
		}
	}
	if cfg.Browser.CORSEnabled || len(cfg.Browser.AllowedOrigins) != 1 || cfg.Browser.AllowedOrigins[0] != cfg.Platform.Origin {
		return fmt.Errorf("platform requires one matching AUTH_ALLOWED_ORIGINS and disabled CORS")
	}
	if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
		return fmt.Errorf("initial platform profile requires direct server TLS")
	}
	reset, err := url.Parse(cfg.Password.ResetURL)
	if err != nil || reset.Scheme+"://"+reset.Host != cfg.Platform.Origin {
		return fmt.Errorf("platform PASSWORD_RESET_URL must use PLATFORM_ORIGIN")
	}
	if err := cfg.Platform.Runtime.Validate(); err != nil {
		return err
	}
	if err := cfg.Platform.Operations.Validate(); err != nil {
		return err
	}
	return cfg.validatePlatformResources()
}
