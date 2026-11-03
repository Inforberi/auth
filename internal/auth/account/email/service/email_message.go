package service

import (
	"context"
	"encoding/json"
	"html"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (s *Verification) send(ctx context.Context, payload []byte) error {
	plain, err := s.cipher.Open(payload)
	if err != nil {
		return err
	}
	var message accountservice.EmailMessage
	if err := json.Unmarshal(plain, &message); err != nil {
		return err
	}
	if message.Subject != "" {
		return s.mail.SendContext(ctx, message.To, message.Subject, message.Body)
	}
	body := `<p>Подтвердите email: <a href="` + html.EscapeString(message.Link) + `">подтвердить адрес</a>.</p>`
	return s.mail.SendContext(ctx, message.To, "Подтверждение email", body)
}
