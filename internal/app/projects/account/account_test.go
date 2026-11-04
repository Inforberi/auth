package account

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
)

func TestProjectAccountURLScope(t *testing.T) {
	cfg := ProjectEmailConfig{Origin: "https://project.example.test", Invitations: accountprovisioning.InvitationConfig{Enabled: true, URL: "https://project.example.test/activate", TTL: time.Hour, ActivationGlobalLimit: 100, ReissueCooldown: time.Minute, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100}, Change: accountemail.EmailChangeConfig{Enabled: true, ConfirmURL: "https://project.example.test/confirm", ReportURL: "https://project.example.test/report", RecoveryURL: "https://project.example.test/recover", TTL: 30 * time.Minute, ProtectionTTL: 24 * time.Hour, RecoveryTTL: 30 * time.Minute}, FreshAuthTTL: 5 * time.Minute}
	require.NoError(t, cfg.validateAccountFeatures())
	foreign := cfg
	foreign.Invitations.URL = "https://platform.example.test/activate"
	require.Error(t, foreign.validateAccountFeatures())
	foreign = cfg
	foreign.Change.ReportURL = "https://other.example.test/report"
	require.Error(t, foreign.validateAccountFeatures())
	foreign = cfg
	foreign.FreshAuthTTL = 0
	require.Error(t, foreign.validateAccountFeatures())
	cfg.Invitations.Enabled, cfg.Change.Enabled = false, false
	cfg.FreshAuthTTL = 0
	require.NoError(t, cfg.validateAccountFeatures())
}

func TestProjectBindingOnlyNeedsNoPasswordResetURL(t *testing.T) {
	cfg := ProjectEmailConfig{Origin: "https://external.example.test", Binding: accountemail.EmailBindingConfig{Enabled: true, TTL: 5 * time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000}}
	require.NoError(t, cfg.validate())
	cfg.RecoveryEnabled = true
	require.Error(t, cfg.validate(), "enabling password recovery must require its actual config")
}
