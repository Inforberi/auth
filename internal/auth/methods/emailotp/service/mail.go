package service

import (
	"encoding/json"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

type codeMail struct {
	To      string `json:"to"`
	Body    string `json:"body"`
	Subject string `json:"subject,omitempty"`
}

func prepareCode(cipher cipher, tokens tokens, ttl time.Duration, email, action, purpose string) (*RequestedCode, domain.Challenge, error) {
	binding, err := tokens.GenerateToken()
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	code, err := tokens.GenerateCode()
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	plain, err := json.Marshal(codeMail{To: email, Subject: "Код для " + action, Body: "<p>Код для " + action + ": <strong>" + code + "</strong>.</p><p>Если вы не запрашивали эту операцию, никому не сообщайте код.</p>"})
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	payload, err := cipher.Seal(plain)
	if err != nil {
		return nil, domain.Challenge{}, err
	}
	result := &RequestedCode{Binding: binding, ExpiresAt: time.Now().UTC().Add(ttl)}
	return result, domain.Challenge{
		Digest:   cipher.Digest(purpose + "binding:" + binding),
		Verifier: cipher.Digest(purpose + "code:" + binding + ":" + code),
		Payload:  payload, ExpiresAt: result.ExpiresAt,
	}, nil
}
