package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

type Cipher struct {
	purpose string
	aead    cipher.AEAD
	key     []byte
}

func New(encoded string) (*Cipher, error) {
	return NewScoped(encoded, "email-verification:v1")
}

func NewScoped(encoded, purpose string) (*Cipher, error) {
	if purpose == "" {
		return nil, errors.New("encryption purpose is required")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid outbox encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead, key: key, purpose: purpose}, nil
}

func (c *Cipher) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plain, []byte(c.purpose)), nil
}

func (c *Cipher) Open(payload []byte) ([]byte, error) {
	size := c.aead.NonceSize()
	if len(payload) < size+c.aead.Overhead() {
		return nil, errors.New("invalid encrypted outbox payload")
	}
	return c.aead.Open(nil, payload[:size], payload[size:], []byte(c.purpose))
}

func (c *Cipher) Digest(value string) string {
	namespace := c.purpose + ":limits:"
	if c.purpose == "email-verification:v1" {
		namespace = "email-verification-limits:v1:"
	}
	h := hmac.New(sha256.New, c.key)
	_, _ = h.Write([]byte(namespace + value))
	return hex.EncodeToString(h.Sum(nil))
}
