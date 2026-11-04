package deployment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestProjectDeploymentSourceIsImmutableAndUsesProjectURLs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Platform.Delivery.Enabled = true
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	cfg.Account.EncryptionKey = "synthetic-platform-secret"
	cfg.Account.URL, cfg.Password.ResetURL = "https://platform.example.test/verify", "https://platform.example.test/reset"
	cfg.Google.ClientSecret = "synthetic-provider-secret"
	cfg.JWT.Enabled = true
	source := projectBrowserDeployment(cfg)
	cfg.Platform.Delivery.Enabled = false
	a, err := source(context.Background(), projectruntime.Key{}, "https://alpha.example.test")
	require.NoError(t, err)
	b, err := source(context.Background(), projectruntime.Key{}, "https://beta.example.test")
	require.NoError(t, err)
	require.Equal(t, "https://alpha.example.test/verify-email", a.Verification.URL)
	require.Equal(t, "https://beta.example.test/reset-password", b.Recovery.ResetURL)
	require.Empty(t, a.Verification.EncryptionKey)
	require.Nil(t, a.Google)
	require.Nil(t, a.Tokens)
	a.Password.Session.SessionTTL = time.Second
	require.NotEqual(t, a.Password.Session.SessionTTL, b.Password.Session.SessionTTL)
}
