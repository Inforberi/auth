package sandbox_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

const sandboxURL = "https://localhost:18443"

func sandboxClient(t *testing.T, browser bool) (*http.Client, *x509.CertPool) {
	t.Helper()
	cert, err := os.ReadFile(filepath.Join(sandboxDirectory(t), "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("invalid sandbox CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if browser {
		jar, jarErr := cookiejar.New(nil)
		if jarErr != nil {
			t.Fatal(jarErr)
		}
		client.Jar = jar
	}
	return client, roots
}

func request(t *testing.T, client *http.Client, method, path string, input, output any, want int, headers ...string) http.Header {
	t.Helper()
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Cleanup restores policy too; t.Context is already cancelled when cleanup runs.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, sandboxURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("sandbox HTTPS request failed", method, path)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil || len(data) > 32768 {
		t.Fatal("invalid sandbox response size/read")
	}
	if resp.StatusCode != want {
		// Bodies may contain passwords, JWT or enrollment material; never print them.
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &failure)
		t.Fatalf("%s %s: got %d, want %d (code %s)", method, path, resp.StatusCode, want, failure.Code)
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		t.Fatal("invalid sandbox response JSON", path)
	}
	return resp.Header
}

func privateJSON(t *testing.T, name string, out any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(sandboxDirectory(t), name))
	if err != nil || json.Unmarshal(data, out) != nil {
		t.Fatal("missing or invalid synthetic fixture", name)
	}
}

func newConsumer(t *testing.T, roots *x509.CertPool, mode string) *authjwt.Consumer {
	t.Helper()
	cfg := authjwt.ConsumerConfig{Expected: authjwt.Expectations{
		Issuer: sandboxURL, Audience: "sandbox-" + string(mode), Mode: mode,
	}, JWKSURL: sandboxURL + "/.well-known/jwks.json", RootCAs: roots}
	if mode == authjwt.Strict {
		secret, err := os.ReadFile(filepath.Join(sandboxDirectory(t), "jwt/consumer-secret"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.IntrospectionURL = sandboxURL + "/api/v1/internal/auth/token/introspect"
		cfg.ClientID, cfg.ClientSecret = "sandbox-consumer", string(secret)
	}
	consumer, err := authjwt.NewConsumer(t.Context(), cfg)
	if err != nil {
		t.Fatal("consumer startup failed")
	}
	t.Cleanup(consumer.Close)
	return consumer
}

func consume(t *testing.T, consumer *authjwt.Consumer, token, permission string, want int, headers ...string) {
	t.Helper()
	guard, err := authjwt.RequirePermissions(permission)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := consumer.Middleware(guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := authjwt.PrincipalFromContext(r.Context())
		if !ok || principal.UserID() == "" {
			t.Error("missing verified principal")
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	req := httptest.NewRequest(http.MethodGet, "https://sandbox-backend.example/records", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != want || called != (want == http.StatusNoContent) {
		t.Fatalf("consumer: got %d, want %d; handler called=%t", response.Code, want, called)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable protected response")
	}
}

func sandboxContainer(t *testing.T, service string) string {
	t.Helper()
	if service != "redis" && service != "postgres" && service != "api" {
		t.Fatal("only sandbox API or dependencies may be stopped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	label, err := exec.CommandContext(ctx, "docker", "inspect", "--format", `{{ index .Config.Labels "com.docker.compose.project" }}`, "auth-sandbox-"+service+"-1").Output()
	if err != nil || strings.TrimSpace(string(label)) != "auth-sandbox" {
		t.Fatal("refusing dependency operation outside auth-sandbox")
	}
	return "auth-sandbox-" + service + "-1"
}

func dockerDependency(t *testing.T, action, service string) {
	t.Helper()
	container := sandboxContainer(t, service)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", action, container).Run(); err != nil {
		t.Fatal("sandbox dependency command failed", action, service)
	}
}

func waitReadiness(t *testing.T, client *http.Client, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 25*time.Second)
	defer cancel()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sandboxURL+"/health/ready", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == want {
				return
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("readiness wait cancelled")
		}
	}
	t.Fatalf("sandbox readiness did not reach %d", want)
}
