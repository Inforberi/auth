package authjwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var ErrAuthorityUnavailable = errors.New("JWT authority unavailable")

type ConsumerConfig struct {
	Expected         Expectations
	JWKSURL          string
	IntrospectionURL string
	ClientID         string
	ClientSecret     string
	RootCAs          *x509.CertPool
}

type Consumer struct {
	config      ConsumerConfig
	client      *http.Client
	transport   *http.Transport
	verifier    *Verifier
	admission   chan struct{}
	closed      atomic.Bool
	mu          sync.Mutex
	lastAttempt time.Time
	pending     chan struct{}
}

// NewConsumer obtains fresh keys before returning; create one instance per configured audience/mode.
func NewConsumer(ctx context.Context, cfg ConsumerConfig) (*Consumer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	transport := consumerTransport(cfg.RootCAs)
	// Do not retain the caller's mutable trust pool.
	cfg.RootCAs = nil
	c := &Consumer{config: cfg, transport: transport, admission: make(chan struct{}, 32)}
	c.client = &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := c.refreshKeys(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (cfg ConsumerConfig) validate() error {
	if cfg.Expected.Validate() != nil || !validEndpoint(cfg.JWKSURL) {
		return ErrConfiguration
	}
	if cfg.Expected.Mode == Local {
		if cfg.IntrospectionURL != "" || cfg.ClientID != "" || cfg.ClientSecret != "" {
			return ErrConfiguration
		}
		return nil
	}
	if !validEndpoint(cfg.IntrospectionURL) || !ValidKeyID(cfg.ClientID) || len(cfg.ClientSecret) != 43 {
		return ErrConfiguration
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(cfg.ClientSecret)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != cfg.ClientSecret {
		return ErrConfiguration
	}
	return nil
}

// Authenticate never returns raw credentials. Strict performs one current online authority decision.
func (c *Consumer) Authenticate(ctx context.Context, raw string) (Principal, error) {
	if len(raw) == 0 || len(raw) > MaxTokenBytes {
		return Principal{}, ErrInvalidToken
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := c.enter(ctx); err != nil {
		return Principal{}, err
	}
	defer func() { <-c.admission }()
	if err := c.refreshKeys(ctx); err != nil {
		return Principal{}, err
	}
	claims, err := c.verifier.VerifySignature(ctx, raw, time.Now())
	if err != nil {
		return Principal{}, err
	}
	scope := claims.Scope
	if c.config.Expected.Mode == Strict {
		scope, err = c.introspect(ctx, raw, claims)
		if err != nil {
			return Principal{}, err
		}
		// Authority I/O must not extend the key snapshot's trust lifetime.
		if err := c.freshKeys(); err != nil {
			return Principal{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return Principal{}, ErrInvalidToken
	}
	return principal(claims, scope), nil
}

// Ready may refresh a due key snapshot. It does not probe/cache an authority decision.
func (c *Consumer) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.admission }()
	return c.refreshKeys(ctx)
}

func (c *Consumer) enter(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.closed.Load() {
		return ErrAuthorityUnavailable
	}
	select {
	case c.admission <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}

// Close rejects new operations and closes idle connections; in-flight calls retain their deadlines.
func (c *Consumer) Close() { c.closed.Store(true); c.transport.CloseIdleConnections() }
