package config

import (
	"os"
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/stretchr/testify/require"
)

func TestProjectEmailMFAEnvironment(t *testing.T) {
	t.Setenv("PLATFORM_PROJECT_HTTP_ENABLED", "false")
	for _, name := range []string{
		"PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_TTL", "PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_RESEND_INTERVAL",
		"PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE", "PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE",
		"PLATFORM_PROJECT_EMAIL_MFA_USER_CHANGES_PER_MINUTE", "PLATFORM_PROJECT_EMAIL_MFA_PROJECT_CHANGES_PER_MINUTE",
	} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
	var c struct{ HTTP ProjectHTTPConfig }
	require.NoError(t, cleanenv.ReadEnv(&c))
	require.False(t, c.HTTP.Enabled)
	require.Equal(t, ProjectEmailMFAConfig{PreparationTTL: 3 * time.Minute, PreparationResendInterval: time.Minute, PreparationRequestsPerProjectMinute: 100, PreparationConfirmsPerProjectMinute: 1000, UserChangesPerMinute: 5, ProjectChangesPerMinute: 500}, c.HTTP.EmailMFA)
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_TTL", "4m")
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_RESEND_INTERVAL", "45s")
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE", "250")
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE", "2000")
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_USER_CHANGES_PER_MINUTE", "8")
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_PROJECT_CHANGES_PER_MINUTE", "750")
	require.NoError(t, cleanenv.ReadEnv(&c))
	require.Equal(t, ProjectEmailMFAConfig{PreparationTTL: 4 * time.Minute, PreparationResendInterval: 45 * time.Second, PreparationRequestsPerProjectMinute: 250, PreparationConfirmsPerProjectMinute: 2000, UserChangesPerMinute: 8, ProjectChangesPerMinute: 750}, c.HTTP.EmailMFA)
	require.False(t, c.HTTP.Enabled, "budgets do not turn on HTTP or select project methods")
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_USER_CHANGES_PER_MINUTE", "0")
	require.NoError(t, cleanenv.ReadEnv(&c))
	require.Zero(t, c.HTTP.EmailMFA.UserChangesPerMinute, "explicit zero must reach validation, not become a default")
	t.Setenv("PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_TTL", "invalid")
	require.Error(t, cleanenv.ReadEnv(&c))
}
