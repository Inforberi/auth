package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func (cfg Config) validateInitialSetup() error {
	if !cfg.InitialSetup.Enabled {
		return nil
	}
	if !cfg.MFA.Enabled {
		return fmt.Errorf("INITIAL_SETUP_ENABLED requires MFA_ENABLED")
	}
	operator, err := base64.RawURLEncoding.DecodeString(cfg.InitialSetup.Secret)
	if err != nil {
		return fmt.Errorf("invalid INITIAL_SETUP_SECRET encoding")
	}
	root, err := base64.StdEncoding.DecodeString(cfg.Account.EncryptionKey)
	if err != nil {
		return fmt.Errorf("invalid EMAIL_OUTBOX_KEY encoding")
	}
	if bytes.Equal(operator, root) {
		return fmt.Errorf("INITIAL_SETUP_SECRET must be separate from EMAIL_OUTBOX_KEY")
	}
	return nil
}
