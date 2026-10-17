package authjwt

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type Verifier struct {
	expected  Expectations
	trust     atomic.Pointer[trustSnapshot]
	admission chan struct{}
}

type trustSnapshot struct {
	keys       *PublicKeys
	observedAt time.Time
}

// trustedAt is the successful trusted fetch time, never a persisted file's mtime.
func NewVerifier(expected Expectations, keys *PublicKeys, trustedAt time.Time) (*Verifier, error) {
	if expected.Validate() != nil || keys == nil || len(keys.keys) == 0 || trustedAt.IsZero() {
		return nil, ErrConfiguration
	}
	v := &Verifier{expected: expected, admission: make(chan struct{}, 32)}
	if err := v.ReplaceKeys(keys, trustedAt); err != nil {
		return nil, err
	}
	return v, nil
}

// ReplaceKeys is called only after a successful trusted fetch, never on a token's unknown kid.
// Swapping the immutable snapshot preserves the shared admission budget during rotation.
func (v *Verifier) ReplaceKeys(keys *PublicKeys, trustedAt time.Time) error {
	if keys == nil || len(keys.keys) == 0 || trustedAt.IsZero() {
		return ErrConfiguration
	}
	next := &trustSnapshot{keys: keys, observedAt: trustedAt}
	for {
		previous := v.trust.Load()
		if previous != nil && !trustedAt.After(previous.observedAt) {
			return ErrConfiguration
		}
		if v.trust.CompareAndSwap(previous, next) {
			return nil
		}
	}
}

// VerifySignature validates crypto/claims only. Strict tokens still require an online authority decision.
func (v *Verifier) VerifySignature(ctx context.Context, raw string, now time.Time) (Claims, error) {
	if err := ctx.Err(); err != nil {
		return Claims{}, err
	}
	select {
	case v.admission <- struct{}{}:
	default:
		return Claims{}, ErrBusy
	}
	defer func() { <-v.admission }()
	trust := v.trust.Load()
	if trust == nil {
		return Claims{}, ErrKeysUnavailable
	}
	if age := now.Sub(trust.observedAt); age < 0 || age >= MaxKeyAge {
		return Claims{}, ErrKeysUnavailable
	}
	claims, err := verifyClaims(raw, trust.keys)
	if err != nil || claims.Validate(v.expected, now) != nil {
		return Claims{}, ErrInvalidToken
	}
	if err := ctx.Err(); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func verifyClaims(raw string, keys *PublicKeys) (Claims, error) {
	header, err := checkCompact(raw)
	if err != nil {
		return Claims{}, err
	}
	key := keys.keys[header.KeyID]
	if key == nil {
		return Claims{}, ErrInvalidToken
	}
	message, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	payload, err := message.Verify(key)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	return decodeClaims(payload)
}
