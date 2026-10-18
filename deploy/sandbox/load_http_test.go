package sandbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type loadCall struct {
	name, method, path, cookie, basic, body string
	allowBusy                               bool
}

type loadResult struct {
	name    string
	status  int
	elapsed time.Duration
	failed  bool
}

type loadInputs struct{ cookie, adminCookie, basic, token string }

func mixedLoadCall(index int, input loadInputs) loadCall {
	call := loadCall{name: "me", method: "GET", path: "/api/v1/auth/me", cookie: input.cookie}
	switch index % 20 {
	case 12, 13, 14, 15, 16:
		call.name, call.path = "access", "/api/v1/auth/access"
	case 17, 18:
		call.name, call.path, call.cookie = "roles", "/api/v1/admin/roles", input.adminCookie
	case 19:
		body, _ := json.Marshal(map[string]string{"token": input.token})
		call = loadCall{name: "introspect", method: "POST", path: "/api/v1/internal/auth/token/introspect", basic: input.basic, body: string(body)}
	}
	return call
}

func executeLoad(ctx context.Context, client *http.Client, call loadCall) loadResult {
	started := time.Now()
	result := loadResult{name: call.name, failed: true}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, call.method, sandboxURL+call.path, bytes.NewBufferString(call.body))
	if err != nil {
		return result
	}
	if call.cookie != "" {
		req.Header.Set("Cookie", call.cookie)
	}
	if call.basic != "" {
		req.Header.Set("Authorization", call.basic)
	}
	if call.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if call.name == "login" {
		req.Header.Set("Origin", sandboxURL)
	}
	response, err := client.Do(req)
	if err != nil {
		result.elapsed = time.Since(started)
		return result
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 32769))
	closeErr := response.Body.Close()
	result.status, result.elapsed = response.StatusCode, time.Since(started)
	if readErr != nil || closeErr != nil || len(data) > 32768 || !json.Valid(data) {
		return result
	}
	if result.status != 200 && (!call.allowBusy || result.status != 503) {
		return result
	}
	if call.name == "introspect" {
		var state struct{ Active bool }
		if json.Unmarshal(data, &state) != nil || !state.Active {
			return result
		}
	}
	result.failed = false
	return result
}

func loadCookie(t *testing.T, client *http.Client) string {
	t.Helper()
	u, err := url.Parse(sandboxURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range client.Jar.Cookies(u) {
		if cookie.Name == "__Host-session" {
			return cookie.Name + "=" + cookie.Value
		}
	}
	t.Fatal("missing synthetic load session")
	return ""
}

func TestMixedLoadProfile(t *testing.T) {
	input := loadInputs{cookie: "synthetic-user", adminCookie: "synthetic-admin", basic: "synthetic-service", token: "synthetic-token"}
	counts := map[string]int{}
	for i := range 20 {
		call := mixedLoadCall(i, input)
		counts[call.name]++
		if call.name == "introspect" && (call.cookie != "" || call.basic != input.basic || !json.Valid([]byte(call.body))) {
			t.Fatal("mixed profile crossed service/browser credential boundaries")
		}
	}
	if counts["me"] != 12 || counts["access"] != 5 || counts["roles"] != 2 || counts["introspect"] != 1 {
		t.Fatal("mixed profile weights changed")
	}
}
