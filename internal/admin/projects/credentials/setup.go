package credentials

import (
	"crypto/sha256"
	"encoding/hex"
)

// SetupProof exposes only the existing setup token digest, never the setup secret or other keys.
type SetupProof struct {
	binding Binding
	digest  string
}

func (c *Codec) OpenSetup(binding Binding, version int, keyID string, payload []byte) (SetupProof, error) {
	value, err := c.open(binding, version, keyID, payload)
	if err != nil {
		return SetupProof{}, err
	}
	defer clear(value.SigningPrivateKey)
	return setupProof(binding, value.SetupSecret), nil
}

func setupProof(binding Binding, secret string) SetupProof {
	if secret == "" {
		return SetupProof{}
	}
	digest := sha256.Sum256([]byte(secret))
	return SetupProof{binding: binding, digest: hex.EncodeToString(digest[:])}
}

func (p SetupProof) Binding() Binding { return p.binding }
func (p SetupProof) Digest() string   { return p.digest }
func (p SetupProof) String() string   { return "[REDACTED setup proof]" }
func (p SetupProof) GoString() string { return p.String() }
func (p SetupProof) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED setup proof]"`), nil
}
