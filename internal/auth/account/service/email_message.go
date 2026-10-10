package service

import (
	"context"
	"encoding/json"
	"html"
)

type emailMessage struct {
	To      string `json:"to"`
	Link    string `json:"link"`
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
}

func (s *Service) send(ctx context.Context, payload []byte) error {
	plain, err := s.cipher.Open(payload)
	if err != nil {
		return err
	}
	var message emailMessage
	if err := json.Unmarshal(plain, &message); err != nil {
		return err
	}
	if message.Subject != "" {
		return s.mail.SendContext(ctx, message.To, message.Subject, message.Body)
	}
	body := `<p>Подтвердите email: <a href="` + html.EscapeString(message.Link) + `">подтвердить адрес</a>.</p>`
	return s.mail.SendContext(ctx, message.To, "Подтверждение email", body)
}
