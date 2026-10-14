package auth

import (
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestMFAPrimaryPolicyUsesEffectiveAdapters(t *testing.T) {
	cfg := &config.Config{}
	allow := mfaPrimaryPolicy(cfg)
	if !allow("password", "") || allow("emailotp", "") || allow("oidc", "https://accounts.google.com") || allow("unknown", "") {
		t.Fatal("disabled methods accepted")
	}
	cfg.EmailOTP.Enabled = true
	cfg.Google.Enabled = true
	if !allow("emailotp", "") || !allow("oidc", cfg.Google.FlowConfig().Issuer) || allow("oidc", "https://foreign.example") {
		t.Fatal("provider policy")
	}
	cfg.Google.Enabled = false
	if allow("oidc", "https://accounts.google.com") {
		t.Fatal("disabled provider still allowed")
	}
}
