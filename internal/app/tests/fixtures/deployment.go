package fixtures

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func WriteProjectManifest(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "projects.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func DeploymentTokenDefaults(cfg *config.Config) {
	cfg.JWT = tokensettings.Config{AccessTTL: 2 * time.Minute, RefreshIdleTTL: time.Hour, RefreshAbsoluteTTL: 2 * time.Hour, ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000, IntrospectionConsumerPerMinute: 100, IntrospectionProjectPerMinute: 1000}
	// Public platform flags and key paths never select a project profile.
	cfg.Google.ClientSecret = "synthetic-platform-provider-secret"
	cfg.Google.IPLimit, cfg.Google.GlobalLimit = 30, 1000
	cfg.Telegram.IPLimit, cfg.Telegram.GlobalLimit = 30, 1000
	// All OTP durations/budgets remain operational defaults.
	cfg.EmailOTP.TTL, cfg.EmailOTP.ResendInterval = 5*time.Minute, time.Minute
	cfg.EmailOTP.RequestGlobalLimit, cfg.EmailOTP.ConfirmGlobalLimit = 100, 1000
}
