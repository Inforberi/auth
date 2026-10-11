package mailer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSendContextRequiresTLS(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy=", legacy), func(t *testing.T) { assertTLSRequired(t, legacy) })
	}
}

func assertTLSRequired(t *testing.T, legacy bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		if _, err := fmt.Fprint(conn, "220 test SMTP\r\n"); err != nil {
			return
		}
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			return
		}
		_, _ = fmt.Fprint(conn, "250 test SMTP\r\n")
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m := New(Config{SMTPHost: host, SMTPPort: port, SMTPFrom: "auth@example.com", SMTPDomain: "example.com", RequireTLS: true})
	var sendErr error
	if legacy {
		sendErr = m.Send("user@example.com", "subject", "body")
	} else {
		sendErr = m.SendContext(context.Background(), "user@example.com", "subject", "body")
	}
	if sendErr == nil || !strings.Contains(sendErr.Error(), "STARTTLS") {
		t.Fatal("plaintext SMTP accepted", sendErr)
	}
	<-done
}

func TestSubjectInjectionRejectedBeforeSMTP(t *testing.T) {
	m := New(Config{SMTPHost: "127.0.0.1", SMTPPort: "1"})
	if err := m.SendContext(t.Context(), "user@example.com", "subject\r\nBcc: victim@example.com", "body"); err == nil || err.Error() != "invalid email subject" {
		t.Fatal("unsafe subject reached SMTP", err)
	}
}

func TestSendContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := New(Config{SMTPHost: "127.0.0.1", SMTPPort: "1"})
	start := time.Now()
	if err := m.SendContext(ctx, "user@example.com", "subject", "body"); err == nil || time.Since(start) > time.Second {
		t.Fatal("canceled delivery blocked")
	}
}
