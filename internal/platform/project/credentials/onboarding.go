package credentials

type OnboardingKeys struct {
	binding       Binding
	encryptionKey string
	setupSecret   string
}

func (c *Codec) OpenOnboarding(binding Binding, version int, keyID string, payload []byte) (OnboardingKeys, error) {
	value, err := c.open(binding, version, keyID, payload)
	if err != nil {
		return OnboardingKeys{}, err
	}
	defer clear(value.SigningPrivateKey)
	return OnboardingKeys{binding: binding, encryptionKey: value.EncryptionKey, setupSecret: value.SetupSecret}, nil
}

func (k OnboardingKeys) Binding() Binding      { return k.binding }
func (k OnboardingKeys) EncryptionKey() string { return k.encryptionKey }
func (k OnboardingKeys) SetupSecret() string   { return k.setupSecret }
func (k OnboardingKeys) Proof() SetupProof     { return setupProof(k.binding, k.setupSecret) }
func (OnboardingKeys) String() string          { return "[REDACTED onboarding keys]" }
func (OnboardingKeys) GoString() string        { return "[REDACTED onboarding keys]" }
func (OnboardingKeys) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED onboarding keys]"`), nil
}
