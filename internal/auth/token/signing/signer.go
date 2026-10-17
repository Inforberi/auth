package signing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type Signer struct {
	issuer    string
	signer    jose.Signer
	public    *authjwt.PublicKeys
	admission chan struct{}
}

type SignedToken struct {
	Raw       string `json:"-"`
	ID        string
	ExpiresAt time.Time
}

func New(issuer, kid string, privatePEM []byte, public *authjwt.PublicKeys) (*Signer, error) {
	if authjwt.ValidateIssuer(issuer) != nil || !authjwt.ValidKeyID(kid) || len(privatePEM) > 16*1024 || public == nil {
		return nil, authjwt.ErrConfiguration
	}
	privatePEM = bytes.TrimSpace(privatePEM)
	if !bytes.HasPrefix(privatePEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, authjwt.ErrConfiguration
	}
	block, rest := pem.Decode(privatePEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, authjwt.ErrConfiguration
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, authjwt.ErrConfiguration
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, authjwt.ErrConfiguration
	}
	encoded, err := key.PublicKey.Bytes()
	if err != nil || !public.Matches(kid, encoded) {
		return nil, authjwt.ErrConfiguration
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", kid))
	if err != nil {
		return nil, authjwt.ErrConfiguration
	}
	return &Signer{issuer: issuer, signer: signer, public: public, admission: make(chan struct{}, 8)}, nil
}

// Sign is a cryptographic primitive for the transaction-owned issuance service, not a login API.
func (s *Signer) Sign(ctx context.Context, claims authjwt.Claims, now time.Time) (*SignedToken, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.admission <- struct{}{}:
	default:
		return nil, authjwt.ErrBusy
	}
	defer func() { <-s.admission }()
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	claims.Issuer, claims.IssuedAt, claims.ID = s.issuer, now.Unix(), base64.RawURLEncoding.EncodeToString(id[:])
	if err := claims.Validate(authjwt.Expectations{Issuer: s.issuer, Audience: claims.Audience, Mode: claims.Mode}, now); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(claims)
	if err != nil || len(payload) > authjwt.MaxPayloadBytes {
		return nil, authjwt.ErrInvalidToken
	}
	message, err := s.signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	raw, err := message.CompactSerialize()
	if err != nil || len(raw) > authjwt.MaxTokenBytes {
		return nil, authjwt.ErrInvalidToken
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &SignedToken{Raw: raw, ID: claims.ID, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC()}, nil
}

func (s *Signer) PublicJWKS() []byte { return s.public.JWKS() }
