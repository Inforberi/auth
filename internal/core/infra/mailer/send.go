package mailer

import (
	"fmt"
	"net/smtp"
	"strings"
)

func (m *Mailer) Send(to, subject, body string) error {
	auth := smtp.PlainAuth("", m.cfg.SMTPUsername, m.cfg.SMTPPassword, m.cfg.SMTPHost)

	addr := fmt.Sprintf("%s:%s", m.cfg.SMTPHost, m.cfg.SMTPPort)

	msg := buildMessage(m.cfg.SMTPFrom, to, subject, body)

	if err := smtp.SendMail(addr, auth, m.cfg.SMTPFrom, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("send email %w", err)
	}
	return nil
}

func buildMessage(from, to, subject, body string) string {
	headers := map[string]string{
		"From":         from,
		"To":           to,
		"Subject":      subject,
		"MIME-Version": "1.0",
		"Content-Type": "text/html; charset=\"utf-8\"",
	}

	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n" + body)

	return sb.String()
}
