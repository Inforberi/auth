package authjwt

import (
	"errors"
	"testing"
	"time"
)

func TestConsumerLifetimesAcrossAuthorityIO(t *testing.T) {
	for _, mode := range []string{"key trust", "access expiry"} {
		t.Run(mode, func(t *testing.T) {
			c, a, key, claims := consumerFixture(t, Strict)
			if mode == "access expiry" {
				claims.ExpiresAt = time.Now().Unix() + 1
			}
			raw := signedClaims(t, key, claims)
			block, started := make(chan struct{}), make(chan struct{}, 1)
			a.mu.Lock()
			a.online.body = activeReply(claims)
			a.online.block = block
			a.online.started = started
			a.mu.Unlock()
			done := make(chan error, 1)
			go func() { _, err := c.Authenticate(t.Context(), raw); done <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("authority request not started")
			}
			want := ErrKeysUnavailable
			if mode == "key trust" {
				ageKeys(c, MaxKeyAge)
			} else {
				want = ErrInvalidToken
				timer := time.NewTimer(time.Until(time.Unix(claims.ExpiresAt, 0).Add(time.Millisecond)))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-t.Context().Done():
					t.Fatal(t.Context().Err())
				}
			}
			close(block)
			if err := <-done; !errors.Is(err, want) {
				t.Fatal("lifetime extended by I/O", err)
			}
		})
	}
}
