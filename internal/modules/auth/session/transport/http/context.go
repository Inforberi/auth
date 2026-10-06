package http

import (
	"context"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

type Auth struct {
	UserID    accountmodel.UserID
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
