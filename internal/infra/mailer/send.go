package mailer

import (
	"context"
	"fmt"
	"strings"
)

func (m *Mailer) Send(to, subject, htmlBody string) error {
	to = strings.TrimSpace(to)

	subject = strings.TrimSpace(subject)

	htmlBody = strings.TrimSpace(htmlBody)

	if to == "" {
		return fmt.Errorf("recipient email is empty")
	}

	if subject == "" {
		return fmt.Errorf("subject is empty")
	}

	if htmlBody == "" {
		return fmt.Errorf("body is empty")
	}

	if err := m.SendContext(context.Background(), to, subject, htmlBody); err != nil {
		return fmt.Errorf("send email %w", err)
	}
	return nil
}
