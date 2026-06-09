package httpx

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

type Auth struct {
	UserID    domain.UserID
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
