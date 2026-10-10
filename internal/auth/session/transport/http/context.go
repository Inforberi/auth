package http

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Auth struct {
	SessionID string
	UserID    accountdomain.UserID
	TokenHash string
}

type authContextKey struct{}

func SetAuthContext(ctx context.Context, auth Auth) context.Context {
	return context.WithValue(ctx, authContextKey{}, auth)
}

func GetAuthContext(ctx context.Context) (Auth, bool) {
	auth, ok := ctx.Value(authContextKey{}).(Auth)
	return auth, ok
}
