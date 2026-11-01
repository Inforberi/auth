package authjwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestStrongMFARoute(t *testing.T) {
	guard, err := RequireStrongMFA(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	for _, tc := range []struct {
		name, method string
		proof        time.Time
		want         int
	}{
		{"totp", "otp", now.Add(-time.Minute), 204},
		{"recovery", "recovery", now.Add(-time.Minute), 204},
		{"legacy", "mfa", now.Add(-time.Minute), 403},
		{"email", "email", now.Add(-time.Minute), 403},
		{"email code", "email_otp", now.Add(-time.Minute), 403},
		{"Telegram code", "telegram_otp", now.Add(-time.Minute), 403},
		{"telegram", "telegram", now.Add(-time.Minute), 403},
		{"missing", "otp", time.Time{}, 403},
		{"stale", "otp", now.Add(-6 * time.Minute), 403},
		{"future", "otp", now.Add(time.Minute), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := Claims{Subject: "verified-user", ExpiresAt: now.Add(time.Hour).Unix(), Methods: []string{"pwd", tc.method}}
			if !tc.proof.IsZero() {
				v := tc.proof.Unix()
				claims.MFATime = &v
			}
			p := principal(claims, "orders.write")
			if !slices.Equal(p.AuthenticationMethods(), claims.Methods) || !p.MFAVerifiedAt().Equal(tc.proof) {
				t.Fatal("principal lost authentication evidence")
			}
			copy := p.AuthenticationMethods()
			copy[1] = "otp"
			claims.Methods[1] = "otp"
			if p.AuthenticationMethods()[1] != tc.method {
				t.Fatal("caller mutated principal methods")
			}
			r := httptest.NewRequest("POST", "https://data.example/orders", nil)
			r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, p))
			response := httptest.NewRecorder()
			guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(response, r)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if tc.want == 403 && response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("rejection can be cached")
			}
		})
	}
	response := httptest.NewRecorder()
	guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("anonymous request passed") })).ServeHTTP(response, httptest.NewRequest("POST", "https://data.example", nil))
	if response.Code != 401 {
		t.Fatalf("anonymous status %d", response.Code)
	}
	p := Principal{userID: "verified-user", methods: []string{"recovery", "pwd"}, mfaVerifiedAt: now.Add(-time.Minute), expiresAt: now.Add(time.Minute)}
	if !p.strongMFAAt(now, 5*time.Minute) {
		t.Fatal("AMR order changed assurance")
	}
	for _, methods := range [][]string{{"otp", "recovery"}, {"pwd", "oidc"}, {"pwd", "otp", "recovery"}} {
		p.methods = methods
		if p.strongMFAAt(now, 5*time.Minute) {
			t.Fatal("invalid AMR combination accepted", methods)
		}
	}
	p.methods = []string{"pwd", "otp"}
	p.expiresAt = now.Add(-time.Minute)
	r := httptest.NewRequest("POST", "https://data.example", nil)
	r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, p))
	response = httptest.NewRecorder()
	guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("expired principal passed") })).ServeHTTP(response, r)
	if response.Code != 401 {
		t.Fatal("expired principal not rejected", response.Code)
	}
	for _, age := range []time.Duration{0, -time.Second, 16 * time.Minute} {
		if _, err := RequireStrongMFA(age); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid freshness accepted", age)
		}
	}
}
