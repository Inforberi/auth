package service

import (
	"net"
	"strconv"
	"strings"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type smtpPolicy struct {
	targets    map[string]bool
	requireTLS bool
}

func newSMTPPolicy(allowed []string, requireTLS bool) (smtpPolicy, error) {
	if len(allowed) == 0 || len(allowed) > 16 {
		return smtpPolicy{}, domain.ErrInvalidSMTP
	}
	p := smtpPolicy{targets: make(map[string]bool), requireTLS: requireTLS}
	for _, target := range allowed {
		host, port, err := net.SplitHostPort(strings.TrimSpace(target))
		number, parseErr := strconv.Atoi(port)
		candidate := domain.SMTPConfig{Host: host, Port: number, Domain: "example.com", From: "auth@example.com"}
		if err != nil || parseErr != nil || candidate.Validate() != nil {
			return smtpPolicy{}, domain.ErrInvalidSMTP
		}
		p.targets[smtpTarget(candidate)] = true
	}
	return p, nil
}

func smtpTarget(c domain.SMTPConfig) string {
	return net.JoinHostPort(strings.ToLower(c.Host), strconv.Itoa(c.Port))
}

func (p smtpPolicy) validate(config domain.SMTPConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if !p.targets[smtpTarget(config)] || p.requireTLS && !config.RequireTLS {
		return domain.ErrInvalidSMTP
	}
	return nil
}

// NewSMTPSeed validates and encrypts bootstrap input, without SQL, Redis or network calls.
func NewSMTPSeed(config domain.SMTPConfig, password string, allowed []string, requireTLS bool, cipher SMTPCipher) (SMTPStored, error) {
	p, err := newSMTPPolicy(allowed, requireTLS)
	if err != nil {
		return SMTPStored{}, err
	}
	return p.seed(config, password, cipher)
}

func (p smtpPolicy) seed(config domain.SMTPConfig, password string, cipher SMTPCipher) (SMTPStored, error) {
	if err := p.validate(config); err != nil {
		return SMTPStored{}, err
	}
	if cipher == nil || !validSMTPPassword(password) || config.Username != "" && password == "" {
		return SMTPStored{}, domain.ErrInvalidSMTP
	}
	plain := []byte(password)
	defer clear(plain)
	encrypted, err := cipher.Seal(plain)
	if err != nil {
		return SMTPStored{}, domain.ErrInvalidSMTP
	}
	return SMTPStored{SMTPSnapshot: domain.SMTPSnapshot{Config: config, PasswordSet: password != ""}, Password: encrypted}, nil
}
