package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

func (m *Mailer) SendContext(ctx context.Context, to, subject, body string) error {
	if strings.ContainsAny(subject, "\r\n") {
		return fmt.Errorf("invalid email subject")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(m.cfg.SMTPHost, m.cfg.SMTPPort))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()                         //nolint:gosec // Preserve the delivery error; closing an already-closed connection is harmless.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) //nolint:gosec // Cancellation must interrupt SMTP I/O.
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, m.cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }() //nolint:gosec // The successful path reports Quit errors; this is failure cleanup.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: m.cfg.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if m.cfg.RequireTLS {
		return fmt.Errorf("SMTP requires STARTTLS")
	}
	if m.cfg.SMTPUsername != "" {
		if err := client.Auth(smtp.PlainAuth("", m.cfg.SMTPUsername, m.cfg.SMTPPassword, m.cfg.SMTPHost)); err != nil {
			return err
		}
	}
	if err := client.Mail(m.cfg.SMTPFrom); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(buildMessage(m.cfg.SMTPFrom, to, subject, body, m.cfg.SMTPDomain))); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
