package authjwt

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestConsumerIntrospectionCorrelation(t *testing.T) {
	c, a, key, claims := consumerFixture(t, Strict)
	claims.Scope = "orders.read orders.write"
	raw := signedClaims(t, key, claims)
	if p, err := c.Authenticate(t.Context(), raw); err != nil || p.HasPermission("orders.write") || !p.HasPermission("orders.read") {
		t.Fatal("effective scope ignored", p, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"issuer":              func(m map[string]any) { m["iss"] = "https://other.example" },
		"user":                func(m map[string]any) { m["sub"] = "33333333-3333-4333-8333-333333333333" },
		"session":             func(m map[string]any) { m["sid"] = "33333333-3333-4333-8333-333333333333" },
		"token":               func(m map[string]any) { m["jti"] = "wrong" },
		"audience":            func(m map[string]any) { m["audience"] = "other" },
		"expiry":              func(m map[string]any) { m["expiresAt"] = claims.ExpiresAt + 1 },
		"scope escalation":    func(m map[string]any) { m["scope"] = "orders.delete" },
		"empty scope":         func(m map[string]any) { m["scope"] = "" },
		"duplicate scope":     func(m map[string]any) { m["scope"] = "orders.read orders.read" },
		"scope order":         func(m map[string]any) { m["scope"] = "orders.write orders.read" },
		"missing active":      func(m map[string]any) { delete(m, "active") },
		"missing subject":     func(m map[string]any) { delete(m, "sub") },
		"null":                func(m map[string]any) { m["iss"] = nil },
		"case":                func(m map[string]any) { delete(m, "iss"); m["ISS"] = claims.Issuer },
		"extra field":         func(m map[string]any) { m["roles"] = []string{"admin"} },
		"false with metadata": func(m map[string]any) { m["active"] = false },
		"active type":         func(m map[string]any) { m["active"] = "true" },
	} {
		t.Run(name, func(t *testing.T) {
			m := make(map[string]any)
			if err := json.Unmarshal([]byte(activeReply(claims)), &m); err != nil {
				t.Fatal(err)
			}
			mutate(m)
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			a.mu.Lock()
			a.online.body = string(data)
			a.mu.Unlock()
			if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatal("uncorrelated response accepted", err)
			}
		})
	}
	for _, body := range []string{`{}`, `{"active":true,"active":false}`, activeReply(claims) + `{}`, strings.Repeat("x", 8193)} {
		a.mu.Lock()
		a.online.body = body
		a.mu.Unlock()
		if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrAuthorityUnavailable) {
			t.Fatal("invalid response accepted", err)
		}
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusFound, http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		a.mu.Lock()
		a.online.status = status
		a.mu.Unlock()
		before := a.onlineCalls.Load()
		want := ErrAuthorityUnavailable
		if status == 429 {
			want = ErrBusy
		}
		if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, want) {
			t.Fatal(status, err)
		}
		if a.onlineCalls.Load() != before+1 {
			t.Fatal("introspection retry")
		}
	}
	a.mu.Lock()
	a.online.status = 200
	a.online.body = activeReply(claims)
	a.online.cache = "public,max-age=60"
	a.mu.Unlock()
	if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatal("cacheable authority response accepted", err)
	}
}

func FuzzCorrelateIntrospection(f *testing.F) {
	claims := testClaims(time.Unix(1792250000, 0))
	for _, seed := range []string{activeReply(claims), `{"active":false}`, `{"active":true,"active":false}`, `{"active":null}`, `[]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		scope, err := correlateIntrospection(data, claims)
		if err != nil {
			return
		}
		if !validScope(scope) {
			t.Fatal("noncanonical active scope")
		}
		for _, key := range strings.Split(scope, " ") {
			if !slices.Contains(strings.Split(claims.Scope, " "), key) {
				t.Fatal("scope expanded")
			}
		}
	})
}
