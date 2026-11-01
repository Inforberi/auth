package config

import "time"

type ProjectEmailMFAConfig struct {
	PreparationTTL                      time.Duration `env:"PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_TTL" env-default:"3m"`
	PreparationResendInterval           time.Duration `env:"PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_RESEND_INTERVAL" env-default:"1m"`
	PreparationRequestsPerProjectMinute int           `env:"PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"100"`
	PreparationConfirmsPerProjectMinute int           `env:"PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"1000"`
	UserChangesPerMinute                int           `env:"PLATFORM_PROJECT_EMAIL_MFA_USER_CHANGES_PER_MINUTE" env-default:"5"`
	ProjectChangesPerMinute             int           `env:"PLATFORM_PROJECT_EMAIL_MFA_PROJECT_CHANGES_PER_MINUTE" env-default:"500"`
}
