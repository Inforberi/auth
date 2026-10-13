package service

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

type codeMail struct {
	To      string `json:"to"`
	Body    string `json:"body"`
	Subject string `json:"subject,omitempty"`
}

func (s *Service) prepareCode(email, action, purpose string) (*RequestedCode, domain.Challenge, error) {
	binding, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	value, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	code := fmt.Sprintf("%08d", value.Int64())
	plain, err := json.Marshal(codeMail{To: email, Subject: "Код для " + action, Body: "<p>Код для " + action + ": <strong>" + code + "</strong>.</p><p>Если вы не запрашивали эту операцию, никому не сообщайте код.</p>"})
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	payload, err := s.cipher.Seal(plain)
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	result := &RequestedCode{Binding: binding, ExpiresAt: time.Now().UTC().Add(s.cfg.TTL)}
	return result, domain.Challenge{
		Digest:   s.cipher.Digest(purpose + "binding:" + binding),
		Verifier: s.cipher.Digest(purpose + "code:" + binding + ":" + code),
		Payload:  payload, ExpiresAt: result.ExpiresAt,
	}, nil
}
