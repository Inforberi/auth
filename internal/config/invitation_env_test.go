package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func TestInvitationConfiguration(t *testing.T) {
	t.Setenv("INVITATIONS_ENABLED", "true")
	t.Setenv("INVITATION_URL", "https://app.example.com/activate")
	t.Setenv("INVITATION_TTL", "48h")
	t.Setenv("ACTIVATION_GLOBAL_LIMIT", "250")
	var cfg accountservice.InvitationConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.TTL != 48*time.Hour || cfg.ActivationGlobalLimit != 250 {
		t.Fatal("invalid parsed configuration")
	}
	if err := cfg.Validate(true); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"http://app.example.com/activate", "https://user:secret@app.example.com/activate", "https://app.example.com/activate?token=x", "https://app.example.com/activate#token=x"} {
		bad := cfg
		bad.URL = url
		if bad.Validate(true) == nil {
			t.Fatal("invalid URL accepted", url)
		}
	}
	bad := cfg
	bad.TTL = 8 * 24 * time.Hour
	if bad.Validate(true) == nil {
		t.Fatal("invalid lifetime accepted")
	}
	bad = cfg
	bad.ActivationGlobalLimit = 0
	if bad.Validate(true) == nil {
		t.Fatal("unbounded activation limit")
	}
	if (accountservice.InvitationConfig{}).Validate(true) != nil {
		t.Fatal("disabled invitations require settings")
	}
}
