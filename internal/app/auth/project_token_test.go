package auth

import (
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestProjectTokensDisabledWithoutDependencies(t *testing.T) {
	service, err := NewProjectTokens(t.Context(), projectruntime.Key{}, ProjectTokenConfig{}, ProjectTokenDependencies{})
	require.NoError(t, err)
	jwks, err := service.PublicJWKS(t.Context())
	require.ErrorIs(t, err, authjwt.ErrConfiguration)
	require.Nil(t, jwks)
	login, err := service.LoginPassword(t.Context(), tokenservice.NativePasswordInput{})
	require.ErrorIs(t, err, tokendomain.ErrNativeDisabled)
	require.Nil(t, login)
}

func TestProjectTokenRedisRejectsRetryingClient(t *testing.T) {
	base := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { require.NoError(t, base.Close()) })
	owner, err := NewProjectTokenRedis(base)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, owner.Close()) })
	// go-redis v9.19 normalizes input MaxRetries=-1 to Options().MaxRetries=0.
	require.Zero(t, owner.Options().MaxRetries)
	require.Equal(t, 3, base.Options().MaxRetries)
	cfg := ProjectTokenConfig{Enabled: true, Issuer: "https://project.example.test", Timeout: time.Second}
	deps := ProjectTokenDependencies{Registry: &projectruntime.Registry{}, Reader: &projectpostgres.RuntimeCredentialReader{}, IssuanceRedis: owner}
	require.NoError(t, cfg.validate(deps))
	deps.IssuanceRedis = base
	require.ErrorIs(t, cfg.validate(deps), authjwt.ErrConfiguration)
	_, err = NewProjectTokenRedis(nil)
	require.ErrorIs(t, err, authjwt.ErrConfiguration)
}
