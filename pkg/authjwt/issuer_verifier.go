package authjwt

import (
	"context"
	"time"
)

// IssuerVerifier checks the issuer's deployment-pinned keyset and resource policies.
// It is not a remote consumer cache: replacing/retiring these keys requires issuer rollout.
// Session authority is still the caller's responsibility.
type IssuerVerifier struct {
	keys      *PublicKeys
	policies  map[string]Expectations
	admission chan struct{}
}

func NewIssuerVerifier(policies []Expectations, keys *PublicKeys) (*IssuerVerifier, error) {
	if keys == nil || len(keys.keys) == 0 || len(policies) == 0 || len(policies) > 32 {
		return nil, ErrConfiguration
	}
	v := &IssuerVerifier{keys: keys, policies: make(map[string]Expectations, len(policies)), admission: make(chan struct{}, 32)}
	for _, expected := range policies {
		if expected.Validate() != nil || expected.Issuer != policies[0].Issuer {
			return nil, ErrConfiguration
		}
		if _, duplicate := v.policies[expected.Audience]; duplicate {
			return nil, ErrConfiguration
		}
		v.policies[expected.Audience] = expected
	}
	return v, nil
}

func (v *IssuerVerifier) VerifySignature(ctx context.Context, raw string, now time.Time) (Claims, error) {
	if err := ctx.Err(); err != nil {
		return Claims{}, err
	}
	select {
	case v.admission <- struct{}{}:
	default:
		return Claims{}, ErrBusy
	}
	defer func() { <-v.admission }()
	claims, err := verifyClaims(raw, v.keys)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	expected, ok := v.policies[claims.Audience]
	if !ok || claims.Validate(expected, now) != nil {
		return Claims{}, ErrInvalidToken
	}
	return claims, ctx.Err()
}
