package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *Service) PrepareVerification(email string) (domain.Verification, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return domain.Verification{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	u, err := url.Parse(s.cfg.URL)
	if err != nil {
		return domain.Verification{}, err
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	plain, err := json.Marshal(emailMessage{To: email, Link: u.String()})
	if err != nil {
		return domain.Verification{}, err
	}
	payload, err := s.cipher.Seal(plain)
	if err != nil {
		return domain.Verification{}, err
	}
	return domain.Verification{Digest: tokenDigest(token), Payload: payload, ExpiresAt: time.Now().UTC().Add(s.cfg.TTL)}, nil
}

func tokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
