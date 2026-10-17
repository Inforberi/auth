package service

import (
	"strings"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

// CreateRefreshFamilyParams belongs to final native login's SQL transaction, not a public HTTP request.
type CreateRefreshFamilyParams struct {
	SessionID string
	Audience  string
	Scope     []accessdomain.PermissionKey
	Verifier  string `json:"-"`
	IdleTTL   time.Duration
}

func (p CreateRefreshFamilyParams) Validate() error {
	if sessiondomain.ValidateID(p.SessionID) != nil || !authjwt.ValidAudience(p.Audience) || !domain.ValidRefreshVerifier(p.Verifier) ||
		p.IdleTTL <= 0 || p.IdleTTL%time.Second != 0 || len(p.Scope) == 0 || len(p.Scope) > 64 {
		return domain.ErrInvalidRefresh
	}
	keys := make([]string, len(p.Scope))
	for i, key := range p.Scope {
		if !accessdomain.ValidKey(string(key)) || i > 0 && p.Scope[i-1] >= key {
			return domain.ErrInvalidRefresh
		}
		keys[i] = string(key)
	}
	if len(strings.Join(keys, " ")) > 2048 {
		return domain.ErrInvalidRefresh
	}
	return nil
}
