package domain

import "testing"

func TestSMTPConfiguration(t *testing.T) {
	base := SMTPConfig{Host: "smtp.example.com", Port: 587, From: "auth@example.com", Domain: "example.com", RequireTLS: true}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SMTPConfig){
		func(c *SMTPConfig) { c.Host = "https://smtp.example.com" },
		func(c *SMTPConfig) { c.Host = "smtp.example.com\r\n" },
		func(c *SMTPConfig) { c.Host = "a@b" },
		func(c *SMTPConfig) { c.Port = 0 },
		func(c *SMTPConfig) { c.Port = 65536 },
		func(c *SMTPConfig) { c.From = "Name <auth@example.com>" },
		func(c *SMTPConfig) { c.Domain = "example.com>\r\nBcc: victim" },
		func(c *SMTPConfig) { c.Username = "user\x00secret" },
	} {
		candidate := base
		change(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatal("invalid SMTP config accepted", candidate)
		}
	}
}
