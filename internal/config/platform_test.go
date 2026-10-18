package config

import "testing"

func TestPlatformProfile(t *testing.T) {
	base := validConfig()
	base.Platform = PlatformConfig{Enabled: true, RealmID: "1c82c477-3a57-4823-8c49-a476550d8a21", Origin: "https://console.auth.example"}
	base.Browser.AllowedOrigins = []string{base.Platform.Origin}
	base.MFA.Enabled = true
	base.Server.TLSCertFile, base.Server.TLSKeyFile = "tls.crt", "tls.key"
	base.Password.ResetURL = base.Platform.Origin + "/reset-password"
	if err := base.ValidatePlatform(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"missing realm":          func(c *Config) { c.Platform.RealmID = "" },
		"zero realm":             func(c *Config) { c.Platform.RealmID = "00000000-0000-0000-0000-000000000000" },
		"wildcard":               func(c *Config) { c.Platform.Origin = "https://*.example.com" },
		"plaintext origin":       func(c *Config) { c.Platform.Origin = "http://console.auth.example" },
		"CORS":                   func(c *Config) { c.Browser.CORSEnabled = true },
		"foreign browser origin": func(c *Config) { c.Browser.AllowedOrigins = []string{"https://project.auth.example"} },
		"no MFA":                 func(c *Config) { c.MFA.Enabled = false },
		"no TLS":                 func(c *Config) { c.Server.TLSCertFile = "" },
		"foreign reset URL":      func(c *Config) { c.Password.ResetURL = "https://project.auth.example/reset" },
		"JWT":                    func(c *Config) { c.JWT.Enabled = true },
		"Google":                 func(c *Config) { c.Google.Enabled = true },
		"Telegram":               func(c *Config) { c.Telegram.Enabled = true },
		"OTP":                    func(c *Config) { c.EmailOTP.Enabled = true },
		"invitations":            func(c *Config) { c.Invitation.Enabled = true },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if err := cfg.ValidatePlatform(); err == nil {
				t.Fatal("invalid platform profile accepted")
			}
		})
	}
	if err := (Config{}).ValidatePlatform(); err != nil {
		t.Fatal("default standalone changed", err)
	}
}
