package credentials

// AuthKey exposes only the project data-encryption key to trusted feature assembly.
type AuthKey struct {
	binding       Binding
	encryptionKey string
}

func (c *Codec) OpenAuth(binding Binding, version int, keyID string, payload []byte) (AuthKey, error) {
	value, err := c.open(binding, version, keyID, payload)
	if err != nil {
		return AuthKey{}, err
	}
	defer clear(value.SigningPrivateKey)
	return AuthKey{binding: binding, encryptionKey: value.EncryptionKey}, nil
}

func (k AuthKey) Binding() Binding           { return k.binding }
func (k AuthKey) EncryptionKey() string      { return k.encryptionKey }
func (AuthKey) String() string               { return "[REDACTED auth key]" }
func (k AuthKey) GoString() string           { return k.String() }
func (AuthKey) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED auth key]"`), nil }
