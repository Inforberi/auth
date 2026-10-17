package mailer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnectionProbeDoesNotSendMail(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	commands := make(chan []string, 1)
	go func() {
		var seen []string
		defer func() { commands <- seen }()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = fmt.Fprint(conn, "220 synthetic SMTP\r\n")
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			seen = append(seen, line)
			if strings.HasPrefix(line, "QUIT") {
				_, _ = fmt.Fprint(conn, "221 bye\r\n")
				return
			}
			_, _ = fmt.Fprint(conn, "250 synthetic\r\n")
		}
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckContext(t.Context(), Config{SMTPHost: host, SMTPPort: port}); err != nil {
		t.Fatal(err)
	}
	seen := strings.Join(<-commands, "")
	if !strings.Contains(seen, "NOOP") || !strings.Contains(seen, "QUIT") || strings.Contains(seen, "MAIL") || strings.Contains(seen, "RCPT") || strings.Contains(seen, "DATA") {
		t.Fatal("probe did more than connection checking", seen)
	}
}

func TestPersistedSourceFailureHasNoFallback(t *testing.T) {
	m := NewWithSource(func(context.Context) (Config, error) { return Config{}, errors.New("private source password") })
	err := m.SendContext(t.Context(), "owner@example.com", "subject", "body")
	if err == nil || strings.Contains(err.Error(), "password") {
		t.Fatal("source failure leaked or fell back", err)
	}
}
