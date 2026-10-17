package authjwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

const keyRefreshInterval = 10 * time.Second

func (c *Consumer) refreshKeys(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if pending := c.pending; pending != nil {
		c.mu.Unlock()
		select {
		case <-pending:
			if err := ctx.Err(); err != nil {
				return err
			}
			return c.freshKeys()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !c.lastAttempt.IsZero() && time.Since(c.lastAttempt) < keyRefreshInterval {
		c.mu.Unlock()
		return c.freshKeys()
	}
	c.lastAttempt = time.Now()
	c.pending = make(chan struct{})
	c.mu.Unlock()
	keys, err := c.fetchKeys(ctx)
	c.mu.Lock()
	if err == nil {
		observedAt := time.Now()
		if c.verifier == nil {
			c.verifier, err = NewVerifier(c.config.Expected, keys, observedAt)
		} else {
			err = c.verifier.ReplaceKeys(keys, observedAt)
		}
	}
	close(c.pending)
	c.pending = nil
	c.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrConfiguration) {
		return ErrKeysUnavailable
	}
	// A failed refresh does not extend trust. A still-fresh snapshot is usable until its original deadline.
	return c.freshKeys()
}

func (c *Consumer) freshKeys() error {
	if c.closed.Load() {
		return ErrAuthorityUnavailable
	}
	c.mu.Lock()
	v := c.verifier
	c.mu.Unlock()
	if v == nil {
		return ErrKeysUnavailable
	}
	trust := v.trust.Load()
	if trust == nil {
		return ErrKeysUnavailable
	}
	if age := time.Since(trust.observedAt); age < 0 || age >= MaxKeyAge {
		return ErrKeysUnavailable
	}
	return nil
}

func (c *Consumer) fetchKeys(ctx context.Context) (*PublicKeys, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// Even an idempotent GET must not escape the fetch-attempt budget through Transport retries.
	var connections atomic.Int32
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(string) {
			if connections.Add(1) > 1 {
				cancel()
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if connections.Load() > 1 {
				if info.Conn.Close() != nil {
					cancel()
				}
			}
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.JWKSURL, nil)
	if err != nil {
		return nil, ErrConfiguration
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	req.Header.Set("Cache-Control", "no-cache, no-store")
	response, err := c.request(req, MaxJWKSBytes)
	if err != nil || response.status != http.StatusOK {
		return nil, ErrKeysUnavailable
	}
	keys, err := ParsePublicKeys(response.data)
	if err != nil {
		return nil, ErrKeysUnavailable
	}
	return keys, nil
}
