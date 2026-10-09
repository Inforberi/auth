package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/url"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type verificationMail struct {
	To   string `json:"to"`
	Link string `json:"link"`
}

func (s *Service) Prepare(email string) (domain.Verification, error) {
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
	plain, err := json.Marshal(verificationMail{To: email, Link: u.String()})
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

func (s *Service) AllowRegistration(ctx context.Context, ip string) error {
	if err := s.limit(ctx, "register-ip:"+ip, 5, time.Minute); err != nil {
		return err
	}
	return s.limit(ctx, "register-global", 100, time.Minute)
}

func (s *Service) Resend(ctx context.Context, input, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.limit(ctx, "resend-ip:"+ip, 10, time.Minute); err != nil {
		return err
	}
	email, err := domain.NewEmail(input)
	if err != nil {
		return err
	}
	if err := s.limit(ctx, "resend-email:"+email.String(), 3, 15*time.Minute); err != nil {
		return err
	}
	prepared, err := s.Prepare(email.String())
	if err != nil {
		return err
	}
	return s.repo.Issue(ctx, email.String(), prepared, s.cfg.ResendInterval)
}

func (s *Service) Confirm(ctx context.Context, token, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.limit(ctx, "confirm-ip:"+ip, 20, time.Minute); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return domain.ErrInvalidVerification
	}
	return s.repo.Confirm(ctx, tokenDigest(token))
}

func (s *Service) send(ctx context.Context, payload []byte) error {
	plain, err := s.cipher.Open(payload)
	if err != nil {
		return err
	}
	var message verificationMail
	if err := json.Unmarshal(plain, &message); err != nil {
		return err
	}
	body := `<p>Подтвердите email: <a href="` + html.EscapeString(message.Link) + `">подтвердить адрес</a>.</p>`
	return s.mail.SendContext(ctx, message.To, "Подтверждение email", body)
}
