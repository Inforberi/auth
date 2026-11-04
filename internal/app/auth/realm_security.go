package auth

import (
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type realmSecurity struct{ scope realmscope.Scope }

func (s realmSecurity) cipher(root, purpose string) (*secretbox.Cipher, error) {
	return secretbox.ForScope(s.scope, root, purpose)
}
