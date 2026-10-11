package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

type RequestedCode struct {
	Binding   string
	ExpiresAt time.Time
}

type loginMail struct {
	To   string `json:"to"`
	Body string `json:"body"`
}

func (s *Service) Request(ctx context.Context, input, ip string) (*RequestedCode, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrDisabled
	}
	email, err := accountdomain.NewEmail(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, budget := range []struct {
		key    string
		count  int
		window time.Duration
	}{
		{"request:ip:" + ip, 10, time.Minute},
		{"request:project", s.cfg.RequestGlobalLimit, time.Minute},
		{"request:email:" + email.String(), 3, 15 * time.Minute},
		{"request:cooldown:" + email.String(), 1, s.cfg.ResendInterval},
	} {
		if err := s.limit(ctx, budget.key, budget.count, budget.window); err != nil {
			return nil, err
		}
	}
	binding, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	value, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return nil, err
	}
	code := fmt.Sprintf("%08d", value.Int64())
	plain, err := json.Marshal(loginMail{To: email.String(), Body: "<p>Код для входа: <strong>" + code + "</strong>.</p><p>Если вы не запрашивали вход, никому не сообщайте код.</p>"})
	if err != nil {
		return nil, err
	}
	payload, err := s.cipher.Seal(plain)
	if err != nil {
		return nil, err
	}
	result := &RequestedCode{Binding: binding, ExpiresAt: time.Now().UTC().Add(s.cfg.TTL)}
	err = s.repo.Issue(ctx, email.String(), domain.Challenge{
		Digest: s.cipher.Digest("binding:" + binding), Verifier: s.cipher.Digest("code:" + binding + ":" + code),
		Payload: payload, ExpiresAt: result.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
