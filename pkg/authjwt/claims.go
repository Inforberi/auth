package authjwt

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	Strict          = "strict"
	Local           = "local"
	MaxLifetime     = 5 * time.Minute
	MaxKeyAge       = time.Minute
	MaxTokenBytes   = 4096
	MaxPayloadBytes = 3072
)

var (
	ErrInvalidToken    = errors.New("invalid access token")
	ErrConfiguration   = errors.New("invalid JWT configuration")
	ErrKeysUnavailable = errors.New("JWT trust snapshot unavailable")
	ErrBusy            = errors.New("JWT capacity exhausted")
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	scopePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	kidPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

type Claims struct {
	Issuer      string   `json:"iss"`
	Subject     string   `json:"sub"`
	SessionID   string   `json:"sid"`
	Audience    string   `json:"aud"`
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
	ID          string   `json:"jti"`
	AuthVersion int64    `json:"auth_version"`
	Scope       string   `json:"scope"`
	Mode        string   `json:"avm"`
	AuthTime    int64    `json:"auth_time"`
	Methods     []string `json:"amr"`
	MFATime     *int64   `json:"mfa_time,omitempty"`
	NotBefore   *int64   `json:"nbf,omitempty"`
}

type Expectations struct {
	Issuer   string
	Audience string
	Mode     string
}

func ValidateIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || len(issuer) > 256 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(issuer, "\r\n\t ") {
		return ErrConfiguration
	}
	return nil
}

func (e Expectations) Validate() error {
	if ValidateIssuer(e.Issuer) != nil || !validAudience(e.Audience) || e.Mode != Strict && e.Mode != Local {
		return ErrConfiguration
	}
	return nil
}

func ValidKeyID(kid string) bool { return kidPattern.MatchString(kid) }

func validAudience(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func validUUID(s string) bool {
	return uuidPattern.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

func validScope(scope string) bool {
	if scope == "" || len(scope) > 2048 {
		return false
	}
	keys := strings.Split(scope, " ")
	if len(keys) > 64 {
		return false
	}
	for i, key := range keys {
		if len(key) > 96 || !scopePattern.MatchString(key) || i > 0 && keys[i-1] >= key {
			return false
		}
	}
	return true
}
