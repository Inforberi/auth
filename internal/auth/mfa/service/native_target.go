package service

import (
	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type NativeTarget struct {
	Audience string
	Scope    []accessdomain.PermissionKey
}

func (t NativeTarget) Validate() error {
	if !authjwt.ValidAudience(t.Audience) || len(t.Scope) == 0 || len(t.Scope) > 64 {
		return domain.ErrProofRequired
	}
	size := 0
	for i, key := range t.Scope {
		if !accessdomain.ValidKey(string(key)) || i > 0 && t.Scope[i-1] >= key {
			return domain.ErrProofRequired
		}
		size += len(key) + 1
	}
	if size-1 > 2048 {
		return domain.ErrProofRequired
	}
	return nil
}
