package authjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type (
	consumerReply struct {
		status             int
		body, media, cache string
		block              <-chan struct{}
		started            chan<- struct{}
		drop               bool
	}
	consumerAuthority struct {
		mu                     sync.Mutex
		keys, online           consumerReply
		jwksCalls, onlineCalls atomic.Int32
		server                 *httptest.Server
		config                 ConsumerConfig
		secret                 string
		t                      *testing.T
	}
)

func (a *consumerAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	reply := a.keys
	if r.URL.Path == "/introspect" {
		reply = a.online
		a.onlineCalls.Add(1)
	} else {
		a.jwksCalls.Add(1)
	}
	a.mu.Unlock()
	if reply.started != nil {
		select {
		case reply.started <- struct{}{}:
		default:
		}
	}
	if reply.block != nil {
		select {
		case <-reply.block:
		case <-r.Context().Done():
			return
		}
	}
	if reply.drop {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			a.t.Error(err)
			return
		}
		_ = conn.Close()
		return
	}
	if r.URL.Path == "/introspect" {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "orders-api" || secret != a.secret || len(r.Header.Values("Authorization")) != 1 || r.Method != "POST" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" || r.URL.RawQuery != "" {
			a.t.Error("wrong service transport")
		}
		var input struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Token == "" {
			a.t.Error("full token not supplied")
		}
	} else if r.Method != "GET" || r.Header.Get("Authorization") != "" {
		a.t.Error("JWKS credential leak")
	}
	w.Header().Set("Content-Type", reply.media)
	w.Header().Set("Cache-Control", reply.cache)
	if reply.status == http.StatusFound {
		w.Header().Set("Location", a.server.URL+"/redirect-target")
	}
	w.WriteHeader(reply.status)
	_, _ = w.Write([]byte(reply.body))
}

func activeReply(c Claims) string {
	data, _ := json.Marshal(map[string]any{"active": true, "iss": c.Issuer, "sub": c.Subject, "sid": c.SessionID, "jti": c.ID, "audience": c.Audience, "expiresAt": c.ExpiresAt, "scope": c.Scope})
	return string(data)
}

func consumerFixture(t *testing.T, mode string) (*Consumer, *consumerAuthority, *ecdsa.PrivateKey, Claims) {
	t.Helper()
	key, jwks := testKey(t, "current")
	claims := testClaims(time.Now().Truncate(time.Second))
	claims.Mode = mode
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	a := &consumerAuthority{t: t, secret: secret, keys: consumerReply{status: 200, body: string(jwks), media: "application/jwk-set+json"}, online: consumerReply{status: 200, body: activeReply(claims), media: "application/json", cache: "no-store"}}
	a.server = httptest.NewTLSServer(a)
	t.Cleanup(a.server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(a.server.Certificate())
	cfg := ConsumerConfig{Expected: Expectations{Issuer: claims.Issuer, Audience: claims.Audience, Mode: mode}, JWKSURL: a.server.URL + "/jwks", RootCAs: roots}
	if mode == Strict {
		cfg.IntrospectionURL = a.server.URL + "/introspect"
		cfg.ClientID = "orders-api"
		cfg.ClientSecret = secret
	}
	a.config = cfg
	c, err := NewConsumer(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, a, key, claims
}

func dueKeys(c *Consumer) {
	c.mu.Lock()
	c.lastAttempt = time.Now().Add(-keyRefreshInterval)
	c.mu.Unlock()
}

func ageKeys(c *Consumer, age time.Duration) {
	trust := c.verifier.trust.Load()
	c.verifier.trust.Store(&trustSnapshot{keys: trust.keys, observedAt: time.Now().Add(-age)})
}

func TestConsumerModesAndCurrentAuthority(t *testing.T) {
	for _, mode := range []string{Local, Strict} {
		t.Run(mode, func(t *testing.T) {
			c, a, key, claims := consumerFixture(t, mode)
			raw := signedClaims(t, key, claims)
			for range 2 {
				p, err := c.Authenticate(t.Context(), raw)
				if err != nil || p.UserID() != claims.Subject || p.SessionID() != claims.SessionID || p.Audience() != claims.Audience || p.ExpiresAt().Unix() != claims.ExpiresAt || !p.HasPermission("orders.read") || p.HasPermission("orders.write") {
					t.Fatal(p, err)
				}
				permissions := p.Permissions()
				permissions[0] = "orders.write"
				if !slices.Equal(p.Permissions(), []string{"orders.read"}) {
					t.Fatal("mutable principal")
				}
			}
			want := int32(0)
			if mode == Strict {
				want = 2
			}
			if a.jwksCalls.Load() != 1 || a.onlineCalls.Load() != want {
				t.Fatal("unexpected network requests", a.jwksCalls.Load(), a.onlineCalls.Load())
			}
			claims.Mode = map[string]string{Local: Strict, Strict: Local}[mode]
			if _, err := c.Authenticate(t.Context(), signedClaims(t, key, claims)); !errors.Is(err, ErrInvalidToken) || a.onlineCalls.Load() != want {
				t.Fatal("mode confusion", err)
			}
			if mode == Strict {
				a.mu.Lock()
				a.online.body = `{"active":false}`
				a.mu.Unlock()
				if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrInvalidToken) {
					t.Fatal("cached positive authority", err)
				}
				a.mu.Lock()
				a.online.status = 503
				a.mu.Unlock()
				if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrAuthorityUnavailable) {
					t.Fatal("local fallback", err)
				}
			}
			c.Close()
			if err := c.Ready(t.Context()); !errors.Is(err, ErrAuthorityUnavailable) {
				t.Fatal("closed consumer ready", err)
			}
		})
	}
}

func TestConsumerJWKSFailureAndRotation(t *testing.T) {
	c, a, key, claims := consumerFixture(t, Local)
	raw := signedClaims(t, key, claims)
	other, newKeys := testKey(t, "next")
	otherData, _ := json.Marshal(claims)
	unknown := signPayload(t, other, "next", otherData)
	for range 20 {
		if _, err := c.Authenticate(t.Context(), unknown); !errors.Is(err, ErrInvalidToken) {
			t.Fatal(err)
		}
	}
	if a.jwksCalls.Load() != 1 {
		t.Fatal("unknown kid forced fetch")
	}
	a.mu.Lock()
	a.keys.status = 503
	a.mu.Unlock()
	dueKeys(c)
	if _, err := c.Authenticate(t.Context(), raw); err != nil {
		t.Fatal("fresh original keys lost", err)
	}
	if a.jwksCalls.Load() != 2 {
		t.Fatal("missing due fetch")
	}
	ageKeys(c, MaxKeyAge)
	if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatal("stale trust accepted", err)
	}
	if a.jwksCalls.Load() != 2 {
		t.Fatal("failed-fetch backoff bypassed")
	}
	a.mu.Lock()
	a.keys.status = 200
	a.keys.body = string(newKeys)
	a.mu.Unlock()
	dueKeys(c)
	if _, err := c.Authenticate(t.Context(), unknown); err != nil {
		t.Fatal("rotation failed", err)
	}
	if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("retired key accepted", err)
	}
	if a.jwksCalls.Load() != 3 {
		t.Fatal("retired key triggered fetch")
	}
	ageKeys(c, -time.Minute)
	if err := c.Ready(t.Context()); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatal("future trust accepted", err)
	}
}

func TestConsumerCoalescesRefresh(t *testing.T) {
	c, a, key, claims := consumerFixture(t, Local)
	raw := signedClaims(t, key, claims)
	block, started := make(chan struct{}), make(chan struct{}, 1)
	a.mu.Lock()
	a.keys.block = block
	a.keys.started = started
	a.mu.Unlock()
	dueKeys(c)
	first := make(chan error, 1)
	go func() { _, err := c.Authenticate(t.Context(), raw); first <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("fetch not started")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := c.Authenticate(t.Context(), raw); err != nil {
				t.Error(err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Authenticate(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(block)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if a.jwksCalls.Load() != 2 {
		t.Fatal("refresh stampede", a.jwksCalls.Load())
	}
}

func TestConsumerConfigurationAndStartup(t *testing.T) {
	c, a, _, _ := consumerFixture(t, Strict)
	for _, mutate := range []func(*ConsumerConfig){
		func(cfg *ConsumerConfig) { cfg.JWKSURL = "http://auth.example/jwks" },
		func(cfg *ConsumerConfig) { cfg.JWKSURL = "https://user:secret@auth.example/jwks" },
		func(cfg *ConsumerConfig) { cfg.JWKSURL = "https://auth.example/jwks?key=secret" },
		func(cfg *ConsumerConfig) { cfg.IntrospectionURL = "http://auth.example/online" },
		func(cfg *ConsumerConfig) { cfg.ClientID = "" }, func(cfg *ConsumerConfig) { cfg.ClientSecret = "bad" },
		func(cfg *ConsumerConfig) { cfg.Expected.Mode = Local }, func(cfg *ConsumerConfig) { cfg.Expected.Mode = "auto" },
	} {
		cfg := a.config
		mutate(&cfg)
		if _, err := NewConsumer(t.Context(), cfg); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid config", err)
		}
	}
	cfg := a.config
	cfg.RootCAs = x509.NewCertPool()
	if _, err := NewConsumer(t.Context(), cfg); err == nil || strings.Contains(err.Error(), a.secret) {
		t.Fatal("TLS trust bypass/leak", err)
	}
	for _, reply := range []consumerReply{{status: 302, media: "application/json"}, {status: 200, media: "text/plain", body: `{}`}, {status: 200, media: "application/json", body: strings.Repeat("x", MaxJWKSBytes+1)}, {status: 200, media: "application/json", body: `{"keys":[]}`}} {
		a.mu.Lock()
		a.keys = reply
		a.mu.Unlock()
		before := a.jwksCalls.Load()
		if _, err := NewConsumer(t.Context(), a.config); err == nil {
			t.Fatal("bad startup JWKS accepted")
		}
		if a.jwksCalls.Load() != before+1 {
			t.Fatal("redirect/retry")
		}
	}
	for range 32 {
		c.admission <- struct{}{}
	}
	if _, err := c.Authenticate(t.Context(), "synthetic"); !errors.Is(err, ErrBusy) {
		t.Fatal("unbounded consumer", err)
	}
	for range 32 {
		<-c.admission
	}
}

func TestConsumerNoTransparentRetry(t *testing.T) {
	for _, mode := range []string{Local, Strict} {
		t.Run(mode, func(t *testing.T) {
			c, a, key, claims := consumerFixture(t, mode)
			raw := signedClaims(t, key, claims)
			if _, err := c.Authenticate(t.Context(), raw); err != nil {
				t.Fatal(err)
			}
			if mode == Local {
				a.mu.Lock()
				a.keys.drop = true
				a.mu.Unlock()
				dueKeys(c)
				before := a.jwksCalls.Load()
				if _, err := c.Authenticate(t.Context(), raw); err != nil {
					t.Fatal("fresh snapshot should survive failed fetch", err)
				}
				if a.jwksCalls.Load() != before+1 {
					t.Fatal("transport retried JWKS")
				}
			} else {
				a.mu.Lock()
				a.online.drop = true
				a.mu.Unlock()
				before := a.onlineCalls.Load()
				if _, err := c.Authenticate(t.Context(), raw); !errors.Is(err, ErrAuthorityUnavailable) {
					t.Fatal(err)
				}
				if a.onlineCalls.Load() != before+1 {
					t.Fatal("transport retried introspection")
				}
			}
		})
	}
}

func TestConsumerCancellationReleasesAdmission(t *testing.T) {
	for _, mode := range []string{Local, Strict} {
		t.Run(mode, func(t *testing.T) {
			c, a, key, claims := consumerFixture(t, mode)
			raw := signedClaims(t, key, claims)
			block, started := make(chan struct{}), make(chan struct{}, 1)
			a.mu.Lock()
			if mode == Local {
				a.keys.block = block
				a.keys.started = started
			} else {
				a.online.block = block
				a.online.started = started
			}
			a.mu.Unlock()
			if mode == Local {
				dueKeys(c)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := c.Authenticate(ctx, raw); done <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("request not started")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled request authorized")
				}
			case <-time.After(time.Second):
				t.Fatal("unbounded cancellation")
			}
			if len(c.admission) != 0 {
				t.Fatal("admission leaked")
			}
			close(block)
			if err := c.Ready(t.Context()); err != nil {
				t.Fatal("cancel poisoned consumer", err)
			}
		})
	}
}
