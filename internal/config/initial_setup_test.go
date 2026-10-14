package config

import (
	"encoding/base64"
	"strings"
	"testing"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func TestInitialSetupDependencies(t *testing.T) {
	var cfg Config
	root := []byte(strings.Repeat("r", 32))
	cfg.Account.EncryptionKey = base64.StdEncoding.EncodeToString(root)
	cfg.InitialSetup = accountservice.SetupConfig{Enabled: true, Secret: base64.RawURLEncoding.EncodeToString(root)}
	if err := cfg.validateInitialSetup(); err == nil {
		t.Fatal("MFA dependency ignored")
	}
	cfg.MFA.Enabled = true
	if err := cfg.validateInitialSetup(); err == nil {
		t.Fatal("root encryption key exposed as operator proof")
	}
	cfg.InitialSetup.Secret = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	if err := cfg.validateInitialSetup(); err != nil {
		t.Fatal(err)
	}
	cfg.InitialSetup.Enabled = false
	cfg.MFA.Enabled = false
	if err := cfg.validateInitialSetup(); err != nil {
		t.Fatal(err)
	}
}
