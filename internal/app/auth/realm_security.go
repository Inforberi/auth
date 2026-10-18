package auth

import (
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type realmSecurity struct{ scope realmscope.Scope }

func (s realmSecurity) cipher(root, purpose string) (*secretbox.Cipher, error) {
	context, err := s.scope.Purpose(purpose)
	if err != nil {
		return nil, err
	}
	return secretbox.NewScoped(root, context)
}
