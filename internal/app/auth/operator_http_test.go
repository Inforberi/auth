package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type operatorMailbox struct{ messages chan string }

func (m *operatorMailbox) SendContext(ctx context.Context, _, _, body string) error {
	select {
	case m.messages <- body:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *operatorMailbox) receive(t *testing.T) string {
	t.Helper()
	select {
	case body := <-m.messages:
		return body
	case <-time.After(10 * time.Second):
		t.Fatal("operator mail delivery timed out")
		return ""
	}
}

type operatorHTTPS struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
	origin string
}

func newOperatorHTTPS(t *testing.T, handler http.Handler, origin string) *operatorHTTPS {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 10 * time.Second
	return &operatorHTTPS{t: t, server: server, client: client, origin: origin}
}

func (h *operatorHTTPS) call(method, path string, input any, cookies []*http.Cookie, expected int) (map[string]json.RawMessage, []*http.Cookie) {
	h.t.Helper()
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			h.t.Fatal(err)
		}
	}
	r, err := http.NewRequestWithContext(h.t.Context(), method, h.server.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	origin, err := url.Parse(h.origin)
	if err != nil {
		h.t.Fatal(err)
	}
	r.Host = origin.Host
	r.Header.Set("Origin", h.origin)
	r.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	response, err := h.client.Do(r)
	if err != nil {
		h.t.Fatal("operator HTTPS request failed", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != expected {
		h.t.Fatalf("%s %s: expected %d, got %d", method, path, expected, response.StatusCode)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		h.t.Fatal("operator response is cacheable")
	}
	var result map[string]json.RawMessage
	data, err := io.ReadAll(io.LimitReader(response.Body, 16384))
	if err != nil {
		h.t.Fatal(err)
	}
	if len(data) > 0 && strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(data, &result); err != nil {
			h.t.Fatal("invalid operator response JSON")
		}
	}
	return result, response.Cookies()
}

func operatorField(t *testing.T, object map[string]json.RawMessage, key string) string {
	t.Helper()
	var value string
	if err := json.Unmarshal(object[key], &value); err != nil || value == "" {
		t.Fatalf("missing operator field %s", key)
	}
	return value
}

func operatorCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value != "" {
			if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("operator cookie attributes are unsafe")
			}
			return cookie
		}
	}
	t.Fatal("missing operator proof cookie")
	return nil
}
