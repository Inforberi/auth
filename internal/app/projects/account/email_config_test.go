package account

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
)

func TestProjectEmailTrustedURLs(t *testing.T) {
	cfg := ProjectEmailConfig{VerificationEnabled: true, RecoveryEnabled: true, Origin: "https://project.example.test", Verification: accountservice.Config{
		URL: "https://project.example.test/verify-email", EncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100,
	}, Password: passwordrecovery.Config{ResetURL: "https://project.example.test/reset-password", ResetTokenTTL: time.Hour, ResetGlobalLimit: 100}}
	require.NoError(t, cfg.validate())
	for _, raw := range []string{"https://platform.example.test/reset", "http://project.example.test/reset", "https://user:secret@project.example.test/reset", "https://project.example.test/reset?next=https://evil.example", "https://project.example.test/reset#fragment"} {
		bad := cfg
		bad.Password.ResetURL = raw
		require.Error(t, bad.validate(), raw)
	}
	cfg.Verification.URL = "https://other.example.test/verify-email"
	require.Error(t, cfg.validate())
}
