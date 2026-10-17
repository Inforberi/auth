package auth

import (
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
)

func TestTokenDeploymentUsesLoadedConfiguration(t *testing.T) {
	cfg := settings.Config{Enabled: true, NativeEnabled: true, IntrospectionClientFile: "/private/service-clients.json", Issuer: "https://auth.example", AccessTTL: 2 * time.Minute, PrivateKeyFile: "/private/signing.pem", KeySetFile: "/private/keys.json"}
	resources := []service.Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read"}}, {Audience: "reports", Mode: "local", Permissions: []accessdomain.PermissionKey{"reports.read"}}}
	result := tokenDeployment(cfg, resources, false, false)
	if !result.Enabled || result.NativeEnabled || result.IntrospectionEnabled || result.Issuer != cfg.Issuer || result.AccessTTLSeconds != 120 || result.Resources[0].Mode != "strict" || result.Resources[1].Mode != "local" {
		t.Fatal(result)
	}
	resources[0].Permissions[0] = "injected.permission"
	if result.Resources[0].Permissions[0] != "orders.read" {
		t.Fatal("mutable deployment view")
	}
	if enabled := tokenDeployment(cfg, resources, true, true); !enabled.NativeEnabled || !enabled.IntrospectionEnabled {
		t.Fatal(enabled)
	}
	cfg.Enabled = false
	if disabled := tokenDeployment(cfg, resources, true, true); disabled.Enabled || disabled.NativeEnabled || disabled.IntrospectionEnabled || disabled.Issuer != "" || disabled.Resources != nil {
		t.Fatal("unloaded metadata", disabled)
	}
}
