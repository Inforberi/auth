package sessiontoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type TokenManager struct{}

func (TokenManager) GenerateSessionToken() (string, error) {
	token := make([]byte, 32)

	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate session token %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (TokenManager) Hash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))

	return hex.EncodeToString(sum[:])
}
