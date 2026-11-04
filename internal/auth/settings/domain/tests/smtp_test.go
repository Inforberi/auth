package domain_test

import (
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestSMTPConfiguration(t *testing.T) {
	base := settingsdomain.SMTPConfig{Host: "smtp.example.com", Port: 587, From: "auth@example.com", Domain: "example.com", RequireTLS: true}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*settingsdomain.SMTPConfig){
		func(c *settingsdomain.SMTPConfig) { c.Host = "https://smtp.example.com" },
		func(c *settingsdomain.SMTPConfig) { c.Host = "smtp.example.com\r\n" },
		func(c *settingsdomain.SMTPConfig) { c.Host = "a@b" },
		func(c *settingsdomain.SMTPConfig) { c.Port = 0 },
		func(c *settingsdomain.SMTPConfig) { c.Port = 65536 },
		func(c *settingsdomain.SMTPConfig) { c.From = "Name <auth@example.com>" },
		func(c *settingsdomain.SMTPConfig) { c.Domain = "example.com>\r\nBcc: victim" },
		func(c *settingsdomain.SMTPConfig) { c.Username = "user\x00secret" },
	} {
		candidate := base
		change(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatal("invalid SMTP config accepted", candidate)
		}
	}
}
