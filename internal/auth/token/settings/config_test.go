package settings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestDeploymentConfig(t *testing.T) {
	for _, key := range []string{
		"JWT_ENABLED", "JWT_ISSUER", "JWT_SIGNING_KEY_ID", "JWT_PRIVATE_KEY_FILE", "JWT_KEYSET_FILE", "JWT_RESOURCE_CONFIG_FILE", "JWT_ACCESS_TTL",
		"JWT_NATIVE_ENABLED", "JWT_REFRESH_IDLE_TTL", "JWT_REFRESH_ABSOLUTE_TTL",
		"JWT_ISSUANCE_ACTOR_LIMIT_PER_MINUTE", "JWT_ISSUANCE_SESSION_LIMIT_PER_MINUTE", "JWT_ISSUANCE_IP_LIMIT_PER_MINUTE", "JWT_ISSUANCE_PROJECT_LIMIT_PER_MINUTE",
	} {
		t.Setenv(key, "synthetic")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	var cfg struct{ JWT Config }
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.JWT.Enabled || cfg.JWT.AccessTTL != 2*time.Minute || cfg.JWT.ActorPerMinute != 30 || cfg.JWT.SessionPerMinute != 10 || cfg.JWT.IPPerMinute != 30 || cfg.JWT.ProjectPerMinute != 3000 {
		t.Fatal("wrong disabled defaults", cfg.JWT)
	}
	if cfg.JWT.NativeEnabled || cfg.JWT.RefreshIdleTTL != 168*time.Hour || cfg.JWT.RefreshAbsoluteTTL != 336*time.Hour {
		t.Fatal("wrong native defaults", cfg.JWT)
	}
	if err := cfg.JWT.Validate(); err != nil {
		t.Fatal(err)
	}
	base := Config{
		Enabled: true, Issuer: "https://auth.example", SigningKeyID: "current", PrivateKeyFile: "private.pem", KeySetFile: "public.json", ResourceFile: "resources.json",
		AccessTTL: 2 * time.Minute, ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000,
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Issuer = "http://auth.example" }, func(c *Config) { c.SigningKeyID = "../key" }, func(c *Config) { c.PrivateKeyFile = "" },
		func(c *Config) { c.KeySetFile = "" }, func(c *Config) { c.ResourceFile = "" }, func(c *Config) { c.AccessTTL = 6 * time.Minute },
		func(c *Config) { c.AccessTTL = 0 }, func(c *Config) { c.AccessTTL = time.Second + 1 }, func(c *Config) { c.ActorPerMinute = 0 },
		func(c *Config) { c.SessionPerMinute = -1 }, func(c *Config) { c.IPPerMinute = 1_000_001 }, func(c *Config) { c.ProjectPerMinute = 0 },
	} {
		candidate := base
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, authjwt.ErrConfiguration) {
			t.Fatal("invalid config accepted", err)
		}
		candidate.Enabled = false
		if err := candidate.Validate(); err != nil {
			t.Fatal("disabled profile requires configuration", err)
		}
	}
	t.Setenv("JWT_NATIVE_ENABLED", "true")
	t.Setenv("JWT_REFRESH_IDLE_TTL", "2h")
	t.Setenv("JWT_REFRESH_ABSOLUTE_TTL", "6h")
	if err := cleanenv.ReadEnv(&cfg); err != nil || !cfg.JWT.NativeEnabled || cfg.JWT.RefreshIdleTTL != 2*time.Hour || cfg.JWT.RefreshAbsoluteTTL != 6*time.Hour {
		t.Fatal("native env ignored", err)
	}
	if err := cfg.JWT.Validate(); !errors.Is(err, authjwt.ErrConfiguration) || !strings.Contains(err.Error(), "JWT_ENABLED") {
		t.Fatal("native allowed without JWT", err)
	}
}

func TestResourceFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resources.json")
	for _, data := range []string{
		`{}`, `null`, `{"resources":null}`, `{"resources":[]}`, `{"Resources":[]}`,
		`{"resources":[],"extra":true}`, `{"resources":[],"resources":[]}`,
		`{"resources":[{"audience":"orders","permissions":["orders.read"],"unknown":true}]}`,
		`{"resources":[{"audience":"orders","permissions":null}]}`,
		`{"resources":[{"audience":"orders","audience":"other","permissions":["orders.read"]}]}`,
		`{"resources":[{"Audience":"orders","permissions":["orders.read"]}]}`,
		`{"resources":[{"audience":"orders","permissions":["orders.read"]}]} {}`,
		strings.Repeat(" ", maxResourceBytes+1),
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadResources(path); !errors.Is(err, authjwt.ErrConfiguration) {
			t.Fatal("invalid resource file accepted", err)
		}
	}
	data := `{"resources":[{"audience":"orders","permissions":["orders.read"]},{"audience":"reports","mode":"local","permissions":["reports.read"]}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	resources, err := LoadResources(path)
	if err != nil || len(resources) != 2 || resources[0].Audience != "orders" || resources[1].Mode != "local" {
		t.Fatal(resources, err)
	}
	if _, err := LoadResources(filepath.Dir(path)); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("directory accepted", err)
	}
	if _, err := LoadResources(path + "missing"); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("missing config accepted", err)
	}
}
