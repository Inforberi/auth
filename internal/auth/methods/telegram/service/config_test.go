package service

import (
	"testing"
)

func TestConfig(t *testing.T) {
	if err := (Config{}).Validate(); err != nil {
		t.Fatal("disabled requires secrets", err)
	}
	base := Config{Enabled: true, ClientID: "123", ClientSecret: "secret", RedirectURI: "https://auth.example/api/v1/auth/telegram/callback", IPLimit: 30, GlobalLimit: 1000}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ClientID = "0123" }, func(c *Config) { c.ClientSecret = "" }, func(c *Config) { c.IPLimit = 0 },
		func(c *Config) { c.RedirectURI = "http://auth.example/api/v1/auth/telegram/callback" },
		func(c *Config) { c.RedirectURI += "?return=https://evil.example" }, func(c *Config) { c.RedirectURI = "https://auth.example/other" },
	} {
		cfg := base
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatal("invalid Telegram config accepted")
		}
	}
}
