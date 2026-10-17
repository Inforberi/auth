package authjwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"
)

const MaxJWKSBytes = 16 * 1024

// PublicKeys is an immutable snapshot. No private key or caller-owned map is retained.
type PublicKeys struct {
	keys    map[string]*ecdsa.PublicKey
	encoded []byte
}

func ParsePublicKeys(data []byte) (*PublicKeys, error) {
	if len(data) > MaxJWKSBytes {
		return nil, ErrConfiguration
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if decodeObject(data, &set, "keys") != nil || len(set.Keys) < 1 || len(set.Keys) > 4 {
		return nil, ErrConfiguration
	}
	result := &PublicKeys{keys: make(map[string]*ecdsa.PublicKey, len(set.Keys))}
	for _, raw := range set.Keys {
		key, err := parsePublicKey(raw)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result.keys[key.KeyID]; duplicate {
			return nil, ErrConfiguration
		}
		result.keys[key.KeyID] = key.Key.(*ecdsa.PublicKey)
	}
	// Retain only validated public data; return copies to avoid mutable trust through a response buffer.
	result.encoded = bytes.Clone(data)
	return result, nil
}

func parsePublicKey(raw []byte) (jose.JSONWebKey, error) {
	var metadata struct {
		Type       string   `json:"kty"`
		Curve      string   `json:"crv"`
		X          string   `json:"x"`
		Y          string   `json:"y"`
		KeyID      string   `json:"kid"`
		Algorithm  string   `json:"alg"`
		Use        string   `json:"use"`
		Operations []string `json:"key_ops"`
	}
	if decodeObject(raw, &metadata, "kty", "crv", "x", "y", "kid", "alg", "use", "key_ops") != nil ||
		metadata.Type != "EC" || metadata.Curve != "P-256" || metadata.Algorithm != "ES256" || metadata.Use != "sig" || !ValidKeyID(metadata.KeyID) ||
		metadata.Operations != nil && (len(metadata.Operations) != 1 || metadata.Operations[0] != "verify") {
		return jose.JSONWebKey{}, ErrConfiguration
	}
	for _, coordinate := range []string{metadata.X, metadata.Y} {
		b, err := decodeSegment(coordinate, 32)
		if err != nil || len(b) != 32 {
			return jose.JSONWebKey{}, ErrConfiguration
		}
	}
	var key jose.JSONWebKey
	if json.Unmarshal(raw, &key) != nil || !key.IsPublic() || !key.Valid() {
		return jose.JSONWebKey{}, ErrConfiguration
	}
	public, ok := key.Key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return jose.JSONWebKey{}, ErrConfiguration
	}
	return key, nil
}

func (k *PublicKeys) JWKS() []byte { return bytes.Clone(k.encoded) }

// Matches accepts SEC 1 bytes rather than mutable affine coordinates.
func (k *PublicKeys) Matches(kid string, encodedPoint []byte) bool {
	if k == nil || len(encodedPoint) != 65 {
		return false
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encodedPoint)
	if err != nil {
		return false
	}
	key := k.keys[kid]
	return key != nil && key.Equal(public)
}
