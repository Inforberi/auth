package mailer

import (
	"fmt"
	"net/smtp"
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

	var auth smtp.Auth
	if m.cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", m.cfg.SMTPUsername, m.cfg.SMTPPassword, m.cfg.SMTPHost)
	}

	addr := fmt.Sprintf("%s:%s", m.cfg.SMTPHost, m.cfg.SMTPPort)

	msg := buildMessage(m.cfg.SMTPFrom, to, subject, htmlBody, m.cfg.SMTPDomain)

	if err := smtp.SendMail(addr, auth, m.cfg.SMTPFrom, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("send email %w", err)
	}
	return nil
}
