package credentials

// DatabaseCredential is a snapshot, not authority to open a project or enable LOGIN.
type DatabaseCredential struct {
	binding  Binding
	password string
}

func (c *Codec) OpenDatabase(binding Binding, version int, keyID string, payload []byte) (DatabaseCredential, error) {
	value, err := c.open(binding, version, keyID, payload)
	if err != nil {
		return DatabaseCredential{}, err
	}
	defer clear(value.SigningPrivateKey)
	return DatabaseCredential{binding: binding, password: value.DatabasePassword}, nil
}

func (c DatabaseCredential) Binding() Binding { return c.binding }

// Password is for trusted connection/credential installation code only, never SQL text or logs.
func (c DatabaseCredential) Password() string { return c.password }

func (c DatabaseCredential) String() string   { return "[REDACTED database credential]" }
func (c DatabaseCredential) GoString() string { return c.String() }

func (c DatabaseCredential) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED database credential]"`), nil
}
