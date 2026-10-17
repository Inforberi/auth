package authjwt

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4/json"
)

// Safe JSON rejects duplicates and matches case exactly; explicit fields also reject aliases/nulls.
func decodeObject(data []byte, target any, fields ...string) error {
	var members map[string]json.RawMessage
	if json.Unmarshal(data, &members) != nil || len(members) == 0 {
		return ErrInvalidToken
	}
	for name, value := range members {
		if !slices.Contains(fields, name) || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalidToken
		}
	}
	if json.Unmarshal(data, target) != nil {
		return ErrInvalidToken
	}
	return nil
}

func decodeSegment(s string, limit int) ([]byte, error) {
	if s == "" || len(s) > base64.RawURLEncoding.EncodedLen(limit) {
		return nil, ErrInvalidToken
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > limit || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrInvalidToken
	}
	return b, nil
}

type protectedHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

func checkCompact(raw string) (protectedHeader, error) {
	var header protectedHeader
	if len(raw) > MaxTokenBytes {
		return header, ErrInvalidToken
	}
	segments := strings.SplitN(raw, ".", 4)
	if len(segments) != 3 {
		return header, ErrInvalidToken
	}
	data, err := decodeSegment(segments[0], 512)
	if err != nil {
		return header, err
	}
	if decodeObject(data, &header, "alg", "kid", "typ") != nil || header.Algorithm != "ES256" || header.Type != "at+jwt" || !ValidKeyID(header.KeyID) {
		return header, ErrInvalidToken
	}
	if _, err := decodeSegment(segments[1], MaxPayloadBytes); err != nil {
		return header, err
	}
	signature, err := decodeSegment(segments[2], 64)
	if err != nil || len(signature) != 64 {
		return header, ErrInvalidToken
	}
	return header, nil
}

func decodeClaims(data []byte) (Claims, error) {
	var claims Claims
	err := decodeObject(data, &claims, "iss", "sub", "sid", "aud", "iat", "exp", "jti", "auth_version", "scope", "avm", "auth_time", "amr", "mfa_time", "nbf")
	return claims, err
}
