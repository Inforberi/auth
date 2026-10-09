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

func TestSendContextSMTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	messages := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			messages <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			messages <- ""
			return
		}
		_, _ = fmt.Fprint(conn, "220 test SMTP\r\n")
		r := bufio.NewReader(conn)
		var payload strings.Builder
		data := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				messages <- payload.String()
				return
			}
			if data {
				if line == ".\r\n" {
					data = false
					_, _ = fmt.Fprint(conn, "250 delivered\r\n")
				} else {
					payload.WriteString(line)
				}
				continue
			}
			switch {
			case strings.HasPrefix(line, "DATA"):
				data = true
				_, _ = fmt.Fprint(conn, "354 send message\r\n")
			case strings.HasPrefix(line, "QUIT"):
				_, _ = fmt.Fprint(conn, "221 bye\r\n")
				messages <- payload.String()
				return
			default:
				_, _ = fmt.Fprint(conn, "250 accepted\r\n")
			}
		}
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m := New(Config{SMTPHost: host, SMTPPort: port, SMTPFrom: "auth@example.com", SMTPDomain: "example.com"})
	if err := m.SendContext(context.Background(), "user@example.com", "verify", "<p>verification link</p>"); err != nil {
		t.Fatal(err)
	}
	payload := <-messages
	if !strings.Contains(payload, "To: user@example.com") || !strings.Contains(payload, "verification link") {
		t.Fatal("SMTP payload not delivered")
	}
}
