package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/smtp"
	"regexp"
	"strings"
	"time"
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

	auth := smtp.PlainAuth("", m.cfg.SMTPUsername, m.cfg.SMTPPassword, m.cfg.SMTPHost)

	addr := fmt.Sprintf("%s:%s", m.cfg.SMTPHost, m.cfg.SMTPPort)

	msg := buildMessage(m.cfg.SMTPFrom, to, subject, htmlBody, m.cfg.SMTPDomain)

	if err := smtp.SendMail(addr, auth, m.cfg.SMTPFrom, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("send email %w", err)
	}
	return nil
}

func buildMessage(from, to, subject, htmlBody, domain string) string {
	boundary := "alt_" + randomHex(12)
	messageID := newMessageID(domain)
	plainBody := htmlToPlain(htmlBody)
	encodedPlain := encodeQuotedPrintable(plainBody)
	encodedHTML := encodeQuotedPrintable(htmlBody)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s\r\n", from))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", to))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", encodeSubject(subject)))
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	sb.WriteString(fmt.Sprintf("Message-ID: %s\r\n", messageID))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
	sb.WriteString("\r\n")

	writePart := func(contentType, encodedBody string) {
		sb.WriteString("--" + boundary + "\r\n")
		sb.WriteString("Content-Type: " + contentType + "\r\n")
		sb.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		sb.WriteString(encodedBody + "\r\n")
	}
	writePart("text/html; charset=UTF-8", encodedHTML)
	writePart("text/plain; charset=UTF-8", encodedPlain)
	sb.WriteString("--" + boundary + "--\r\n")

	return sb.String()
}

func htmlToPlain(html string) string {
	blockTags := regexp.MustCompile(`(?i)</?(div|p|h[1-6]|ul|ol|li|br)[^>]*>`)
	allTags := regexp.MustCompile(`<[^>]+>`)

	html = blockTags.ReplaceAllString(html, "\n")
	plain := allTags.ReplaceAllString(html, "")

	lines := strings.Split(plain, "\n")

	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	plain = strings.Join(lines, "\n")

	return strings.TrimSpace(plain)
}

func randomHex(n int) string {
	b := make([]byte, n)

	rand.Read(b)

	return hex.EncodeToString(b)
}

func encodeQuotedPrintable(text string) string {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	w.Write([]byte(text))
	w.Close()

	return buf.String()
}

func encodeSubject(subject string) string {
	if subject == "" {
		return subject
	}
	return mime.QEncoding.Encode("utf-8", subject)
}

func newMessageID(domain string) string {
	random := randomHex(16)
	return fmt.Sprintf("<%s@%s>", random, domain)
}
