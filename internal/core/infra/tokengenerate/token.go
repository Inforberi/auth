package tokengenerate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type TokenManager struct {
	defaultLength int
}

func New() *TokenManager {
	return &TokenManager{
		defaultLength: 32,
	}
}

func (t *TokenManager) GenerateToken(lengths ...int) (string, error) {
	length := t.defaultLength
	if len(lengths) > 0 {
		length = lengths[0]
	}
	token := make([]byte, length)

	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate token %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (TokenManager) Hash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))

	return hex.EncodeToString(sum[:])
}
