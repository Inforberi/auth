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
	cfg := m.cfg
	if m.source != nil {
		var err error
		cfg, err = m.source(ctx)
		if err != nil {
			return fmt.Errorf("SMTP configuration unavailable")
		}
	}
	return withSMTPClient(ctx, cfg, func(client *smtp.Client) error {
		if err := client.Mail(cfg.SMTPFrom); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(buildMessage(cfg.SMTPFrom, to, subject, body, cfg.SMTPDomain))); err != nil {
			return err
		}
		return w.Close()
	})
}

// CheckContext tests greeting/TLS/AUTH/NOOP, not delivery or recipient ownership.
func CheckContext(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return withSMTPClient(ctx, cfg, func(client *smtp.Client) error { return client.Noop() })
}

func withSMTPClient(ctx context.Context, cfg Config, operation func(*smtp.Client) error) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.SMTPHost, cfg.SMTPPort))
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
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }() //nolint:gosec // The successful path reports Quit errors; this is failure cleanup.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if cfg.RequireTLS {
		return fmt.Errorf("SMTP requires STARTTLS")
	}
	if cfg.SMTPUsername != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)); err != nil {
			return err
		}
	}
	if err := operation(client); err != nil {
		return err
	}
	return client.Quit()
}
