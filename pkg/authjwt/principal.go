package authjwt

import (
	"context"
	"slices"
	"strings"
	"time"
)

type Principal struct {
	userID        string
	sessionID     string
	audience      string
	expiresAt     time.Time
	permissions   []string
	methods       []string
	mfaVerifiedAt time.Time
}

func principal(claims Claims, scope string) Principal {
	p := Principal{userID: claims.Subject, sessionID: claims.SessionID, audience: claims.Audience, expiresAt: time.Unix(claims.ExpiresAt, 0), permissions: strings.Split(scope, " "), methods: slices.Clone(claims.Methods)}
	if claims.MFATime != nil {
		p.mfaVerifiedAt = time.Unix(*claims.MFATime, 0)
	}
	return p
}

func (p Principal) UserID() string                  { return p.userID }
func (p Principal) SessionID() string               { return p.sessionID }
func (p Principal) Audience() string                { return p.audience }
func (p Principal) ExpiresAt() time.Time            { return p.expiresAt }
func (p Principal) Permissions() []string           { return slices.Clone(p.permissions) }
func (p Principal) AuthenticationMethods() []string { return slices.Clone(p.methods) }
func (p Principal) MFAVerifiedAt() time.Time        { return p.mfaVerifiedAt }
func (p Principal) HasPermission(key string) bool {
	_, found := slices.BinarySearch(p.permissions, key)
	return found
}

type principalContextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok && p.userID != ""
}
