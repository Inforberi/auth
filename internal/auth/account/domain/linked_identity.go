package domain

import (
	"errors"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidIdentity     = errors.New("invalid external identity")
	ErrIdentityNotFound    = errors.New("external identity not found")
	ErrIdentityUnavailable = errors.New("external identity account unavailable")
)

// IdentityKey is supplied only after the method adapter verifies the provider proof.
// Issuer and subject are opaque, case-sensitive identifiers, never an email match.
type IdentityKey struct {
	Issuer  string
	Subject string
}

func (key IdentityKey) Validate() error {
	for _, part := range []struct {
		value string
		limit int
	}{{key.Issuer, 512}, {key.Subject, 255}} {
		if len(part.value) > part.limit || strings.TrimSpace(part.value) == "" ||
			!utf8.ValidString(part.value) || strings.ContainsRune(part.value, '\x00') {
			return ErrInvalidIdentity
		}
	}
	return nil
}
