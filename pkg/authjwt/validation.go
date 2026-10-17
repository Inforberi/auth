package authjwt

import (
	"encoding/base64"
	"time"
)

// Validate checks protocol invariants, not current permissions or session authority.
func (c Claims) Validate(expected Expectations, now time.Time) error {
	if c.Issuer != expected.Issuer || c.Audience != expected.Audience || !ValidAudience(c.Audience) || c.Mode != expected.Mode || c.Mode != Strict && c.Mode != Local ||
		!validUUID(c.Subject) || !validUUID(c.SessionID) || c.AuthVersion < 1 || !validScope(c.Scope) {
		return ErrInvalidToken
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(c.ID)
	if err != nil || len(id) != 32 || base64.RawURLEncoding.EncodeToString(id) != c.ID {
		return ErrInvalidToken
	}
	if !c.validTimes(now.Unix()) || !c.validProof() {
		return ErrInvalidToken
	}
	return nil
}

func (c Claims) validTimes(timestamp int64) bool {
	// Bound before subtracting so hostile int64 timestamps cannot overflow arithmetic.
	if timestamp <= 0 || c.IssuedAt <= 0 || c.ExpiresAt <= timestamp || c.ExpiresAt <= c.IssuedAt ||
		c.IssuedAt > timestamp+30 || c.ExpiresAt-c.IssuedAt > int64(MaxLifetime/time.Second) || c.AuthTime <= 0 || c.AuthTime > c.IssuedAt {
		return false
	}
	if c.NotBefore != nil && (*c.NotBefore <= 0 || *c.NotBefore > timestamp+30 || *c.NotBefore >= c.ExpiresAt) {
		return false
	}
	return c.MFATime == nil || *c.MFATime >= c.AuthTime && *c.MFATime <= c.IssuedAt
}

func (c Claims) validProof() bool {
	if len(c.Methods) < 1 || len(c.Methods) > 2 {
		return false
	}
	seen := make(map[string]bool, len(c.Methods))
	primary, factors := 0, 0
	for _, method := range c.Methods {
		if seen[method] {
			return false
		}
		seen[method] = true
		switch method {
		case "pwd", "emailotp", "oidc":
			primary++
		case "mfa", "otp", "recovery":
			factors++
		default:
			return false
		}
	}
	return primary == 1 && (factors == 1) == (c.MFATime != nil)
}
