package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func loadEmailMFADeployment(t *testing.T, f emailMFAHTTPFixture, smtpTargets []string) *appauth.ProjectAuthDeployment {
	t.Helper()
	projects := f.projects
	cfg := &config.Config{
		MFA: projects.password.MFA, Session: projects.password.Session, Capacity: projects.password.Capacity,
		Account:  accountservice.Config{TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 10, RegistrationGlobalLimit: 100},
		Password: passwordservice.Config{ResetTokenTTL: time.Hour, ResetGlobalLimit: 100},
	}
	cfg.MFA.RecoveryEnabled = false
	cfg.Platform.RealmID = string(projects.projects[0].Binding.RealmID)
	cfg.Platform.HTTP.BuildTimeout = 10 * time.Second
	cfg.Platform.Delivery.Enabled = true
	cfg.Platform.Delivery.SMTPAllowedTargets = strings.Join(smtpTargets, ",")
	c := f.config
	cfg.Platform.HTTP.EmailMFA = config.ProjectEmailMFAConfig{PreparationTTL: c.Preparation.TTL, PreparationResendInterval: c.Preparation.ResendInterval, PreparationRequestsPerProjectMinute: c.Preparation.RequestsPerMinute, PreparationConfirmsPerProjectMinute: c.Preparation.ConfirmationsPerMinute, UserChangesPerMinute: c.Factors.UserMutationsPerMinute, ProjectChangesPerMinute: c.Factors.ProjectMutationsPerMinute}
	tokens := f.tokens.configs[0]
	cfg.JWT = tokensettings.Config{
		AccessTTL: tokens.Tokens.AccessTTL, RefreshIdleTTL: tokens.Tokens.Native.IdleTTL, RefreshAbsoluteTTL: tokens.Tokens.Native.AbsoluteTTL,
		ActorPerMinute: tokens.Limits.ActorPerMinute, SessionPerMinute: tokens.Limits.SessionPerMinute, IPPerMinute: tokens.Limits.IPPerMinute, ProjectPerMinute: tokens.Limits.ProjectPerMinute,
	}
	var entries []map[string]any
	for i, key := range projects.projects {
		entries = append(entries, map[string]any{
			"id": key.Binding.ProjectID, "browser": true, "emailMFA": true, "mfaSettings": true,
			"jwt": map[string]any{"native": true, "password": true, "permissions": []map[string]string{{"key": "reports.read", "name": "Read reports"}}, "resources": f.tokens.configs[i].Tokens.Resources},
		})
	}
	manifest, err := json.Marshal(map[string]any{"version": 1, "projects": entries})
	require.NoError(t, err)
	cfg.Platform.HTTP.ManifestFile = filepath.Join(t.TempDir(), "project-auth.json")
	require.NoError(t, os.WriteFile(cfg.Platform.HTTP.ManifestFile, manifest, 0o600))
	deployment, err := appauth.LoadProjectAuthDeployment(cfg)
	require.NoError(t, err)
	require.False(t, cfg.MFA.RecoveryEnabled, "project email opt-in must not enable operator recovery")
	return deployment
}
