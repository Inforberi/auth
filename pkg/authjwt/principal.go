package authjwt

import (
	"context"
	"slices"
	"strings"
	"time"
)

type Principal struct {
	userID      string
	sessionID   string
	audience    string
	expiresAt   time.Time
	permissions []string
}

func principal(claims Claims, scope string) Principal {
	return Principal{userID: claims.Subject, sessionID: claims.SessionID, audience: claims.Audience, expiresAt: time.Unix(claims.ExpiresAt, 0), permissions: strings.Split(scope, " ")}
}

func (p Principal) UserID() string        { return p.userID }
func (p Principal) SessionID() string     { return p.sessionID }
func (p Principal) Audience() string      { return p.audience }
func (p Principal) ExpiresAt() time.Time  { return p.expiresAt }
func (p Principal) Permissions() []string { return slices.Clone(p.permissions) }
func (p Principal) HasPermission(key string) bool {
	_, found := slices.BinarySearch(p.permissions, key)
	return found
}

type principalContextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok && p.userID != ""
}
