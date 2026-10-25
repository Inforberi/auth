package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func TestProjectRegistrationVerificationConfiguration(t *testing.T) {
	scope, err := realmscope.New("project", "a9100000-0000-4000-8000-000000000001")
	require.NoError(t, err)
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	cfg := &ProjectRegistrationVerification{Origin: "https://registration.example.test", Config: accountservice.Config{
		URL: "https://registration.example.test/verify-email", EncryptionKey: "caller-key-must-not-select-project", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100,
	}}
	verification, err := newProjectRegistration(scope, root, cfg, rdb)
	require.NoError(t, err)
	require.True(t, verification.configured)
	require.Empty(t, verification.cfg.EncryptionKey)
	require.Equal(t, "caller-key-must-not-select-project", cfg.Config.EncryptionKey)
	original := verification.cfg.URL
	cfg.Config.URL = "https://foreign.example.test/verify"
	require.Equal(t, original, verification.cfg.URL, "caller mutation must not change the constructed verifier")
	_, err = newProjectRegistration(scope, root, cfg, rdb)
	require.Error(t, err)
	disabled, err := newProjectRegistration(scope, root, nil, rdb)
	require.NoError(t, err)
	require.False(t, disabled.configured, "disabled verification needs neither URL nor SMTP")
}
