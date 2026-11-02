package credentials

// SigningKey carries only the prepared signing material, never database/setup credentials.
type SigningKey struct {
	id      string
	private []byte
}

func (c *Codec) OpenSigning(binding Binding, version int, keyID string, payload []byte) (SigningKey, error) {
	value, err := c.open(binding, version, keyID, payload)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{id: value.SigningKeyID, private: value.SigningPrivateKey}, nil
}

// Use consumes the private buffer even if construction fails. The callback must not retain it.
func (k *SigningKey) Use(consume func(string, []byte) error) error {
	defer k.Clear()
	return consume(k.id, k.private)
}

func (k *SigningKey) Clear()                    { clear(k.private); k.private = nil }
func (SigningKey) String() string               { return "[REDACTED signing key]" }
func (k SigningKey) GoString() string           { return k.String() }
func (SigningKey) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED signing key]"`), nil }
