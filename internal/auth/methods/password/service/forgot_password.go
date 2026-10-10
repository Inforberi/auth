package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/templates"
)

type resetMail struct {
	To   string
	Body string
}

func resetDigest(token string) string {
	d := sha256.Sum256([]byte(token))
	return hex.EncodeToString(d[:])
}

func (r *RecoveryService) Forgot(ctx context.Context, input, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.limit(ctx, "forgot-ip:"+ip, 10, time.Minute); err != nil {
		return err
	}
	email, err := accountdomain.NewEmail(input)
	if err != nil {
		return err
	}
	if err := r.limit(ctx, "forgot-email:"+email.String(), 3, 15*time.Minute); err != nil {
		return err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	now := time.Now().UTC()
	body, err := templates.RenderResetPassword(r.cfg.ResetURL, token, r.cfg.ResetTokenTTL, now)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(resetMail{To: email.String(), Body: body})
	if err != nil {
		return err
	}
	payload, err := r.cipher.Seal(plain)
	if err != nil {
		return err
	}
	return r.repo.IssueReset(ctx, email.String(), domain.ResetChallenge{Digest: resetDigest(token), Payload: payload, ExpiresAt: now.Add(r.cfg.ResetTokenTTL)})
}
