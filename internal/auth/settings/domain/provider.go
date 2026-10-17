package domain

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrInvalidProvider     = errors.New("invalid provider settings")
	ErrProviderClientBound = errors.New("provider client is bound to existing identities")
	ErrProviderRevision    = errors.New("provider credentials changed; restart login")
	googleClientID         = regexp.MustCompile(`^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$`)
)

func ValidProvider(name string) bool { return name == "google" || name == "telegram" }

func ValidProviderClientID(name, id string) bool {
	if len(id) > 512 || id == "" {
		return false
	}
	switch name {
	case "google":
		return googleClientID.MatchString(id)
	case "telegram":
		value, err := strconv.ParseUint(id, 10, 64)
		return err == nil && value != 0 && strconv.FormatUint(value, 10) == id
	}
	return false
}

func ValidProviderSecret(secret string) bool {
	return len(secret) <= 1024 && !strings.ContainsAny(secret, "\x00\r\n") && (secret == "" || strings.TrimSpace(secret) != "")
}

func ProviderIssuer(name string) string {
	switch name {
	case "google":
		return "https://accounts.google.com"
	case "telegram":
		return "https://oauth.telegram.org"
	}
	return ""
}

type ProviderSnapshot struct {
	Provider  string `json:"provider"`
	Version   int64  `json:"version"`
	ClientID  string `json:"clientId"`
	SecretSet bool   `json:"clientSecretSet"`
}
