package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
)

func NewEmailToken() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret[:]), nil
}

func EmailTokenLink(address, token string) (string, error) {
	// Startup validation supplies trusted URLs; fragments keep tokens out of access logs/referrers.
	u, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	u.Fragment = "token=" + token
	return u.String(), nil
}

func TokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
