package service

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"time"
)

type Config struct {
	URL            string        `env:"EMAIL_VERIFICATION_URL" env-required:"true"`
	EncryptionKey  string        `env:"EMAIL_OUTBOX_KEY" env-required:"true"`
	TTL            time.Duration `env:"EMAIL_VERIFICATION_TTL" env-default:"30m"`
	ResendInterval time.Duration `env:"EMAIL_VERIFICATION_RESEND_INTERVAL" env-default:"1m"`
}

func (c Config) Validate(production bool) error {
	u, err := url.Parse(c.URL)
	if err != nil || len(c.URL) > 2048 || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("invalid EMAIL_VERIFICATION_URL")
	}
	if production && u.Scheme != "https" {
		return fmt.Errorf("production verification URL must use HTTPS")
	}
	key, err := base64.StdEncoding.DecodeString(c.EncryptionKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("EMAIL_OUTBOX_KEY must encode 32 random bytes in base64")
	}
	if production && (c.EncryptionKey == "bG9jYWwtb25seS1hdXRoLW91dGJveC1rZXktMzJieXQ=" || c.EncryptionKey == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		return fmt.Errorf("production outbox requires a separate random key")
	}
	if c.TTL < time.Minute || c.TTL > time.Hour || c.ResendInterval < time.Minute || c.ResendInterval >= c.TTL {
		return fmt.Errorf("invalid email verification durations")
	}
	return nil
}
