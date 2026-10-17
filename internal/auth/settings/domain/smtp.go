package domain

import (
	"errors"
	"net"
	"net/mail"
	"regexp"
	"strings"
)

var ErrInvalidSMTP = errors.New("invalid SMTP settings")

var smtpHostname = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

type SMTPConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	From       string `json:"from"`
	Domain     string `json:"domain"`
	RequireTLS bool   `json:"requireTls"`
}

type SMTPSnapshot struct {
	Version     int64      `json:"version"`
	Config      SMTPConfig `json:"config"`
	PasswordSet bool       `json:"passwordSet"`
}

func (c SMTPConfig) Validate() error {
	from, err := mail.ParseAddress(c.From)
	if err != nil || from.Address != c.From || len(c.From) > 255 || strings.ContainsAny(c.From, "\r\n\x00") ||
		!validSMTPHost(c.Host) || !validSMTPHost(c.Domain) || c.Port < 1 || c.Port > 65535 ||
		len(c.Username) > 256 || strings.ContainsAny(c.Username, "\r\n\x00") {
		return ErrInvalidSMTP
	}
	return nil
}

func validSMTPHost(value string) bool {
	return len(value) > 0 && len(value) <= 253 && (net.ParseIP(value) != nil || smtpHostname.MatchString(value))
}
