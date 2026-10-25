package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/go-jose/go-jose/v4"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

// FromPrepared derives public metadata from a trusted prepared key, then applies the normal signer checks.
func FromPrepared(issuer, kid string, private []byte) (*Signer, error) {
	if len(private) > 16*1024 {
		return nil, authjwt.ErrConfiguration
	}
	block, rest := pem.Decode(private)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
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
	encoded, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		return nil, authjwt.ErrConfiguration
	}
	public, err := authjwt.ParsePublicKeys(encoded)
	if err != nil {
		return nil, err
	}
	return New(issuer, kid, private, public)
}
