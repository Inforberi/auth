package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
)

const (
	RefreshRotationInterval = 30 * time.Second
	MaxRefreshGenerations   = 4096
)

var (
	ErrInvalidRefresh = errors.New("invalid refresh credential")
	ErrRefreshEarly   = errors.New("refresh rotation too early")
	ErrRefreshLimit   = errors.New("refresh family exhausted; login required")
)

// RefreshVerifier accepts only canonical 256-bit opaque credentials, never JWTs or caller-selected IDs.
func RefreshVerifier(raw string) (string, error) {
	if len(raw) != 43 {
		return "", ErrInvalidRefresh
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return "", ErrInvalidRefresh
	}
	clear(decoded)
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:]), nil
}

func ValidRefreshVerifier(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type RefreshFamily struct {
	SessionID         string
	Audience          string
	Scope             []accessdomain.PermissionKey
	AbsoluteExpiresAt time.Time
	LastRotatedAt     time.Time
	IdleSeconds       int64
	Generation        int
	RevokedAt         *time.Time
}

type RefreshRotation struct {
	Family RefreshFamily
	// Reused is a committed-security-outcome candidate, not an error that should cause rollback.
	Reused bool
}
