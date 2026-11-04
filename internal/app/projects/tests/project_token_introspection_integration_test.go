package projects_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectnative "github.com/Inforberi/financial-intelligence/internal/app/projects/native"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (f projectTokenFixture) introspectionIsolation(t *testing.T, ctx context.Context, service *projectnative.ProjectTokens, cfg projectnative.ProjectTokenConfig, issuanceRedis *redis.Client, input tokenservice.ExchangeInput, raw string) {
	t.Helper()
	consumer, ok := service.Authenticate(tokenConsumerID, tokenConsumerSecret)
	require.True(t, ok)
	active, err := service.Inspect(ctx, consumer, raw)
	require.NoError(t, err)
	require.True(t, active.Active)
	require.Equal(t, tokenFixtureUsers[0], active.Subject)
	require.Equal(t, string(tokenFixturePermission), active.Scope)
	for _, credentials := range [][2]string{{"unknown", tokenConsumerSecret}, {tokenConsumerID, "wrong"}} {
		client, ok := service.Authenticate(credentials[0], credentials[1])
		require.False(t, ok)
		require.Nil(t, client)
	}
	invalid, err := service.Inspect(ctx, consumer, "invalid-token")
	require.NoError(t, err)
	require.Equal(t, tokenservice.IntrospectionResult{}, invalid)
	restricted := input
	restricted.Audience = "reports-export"
	exported, err := service.Exchange(ctx, restricted)
	require.NoError(t, err)
	forbidden, err := service.Inspect(ctx, consumer, exported.Raw)
	require.ErrorIs(t, err, tokendomain.ErrForbidden)
	require.Equal(t, tokenservice.IntrospectionResult{}, forbidden)
	// Independent manifests deliberately reuse a client ID; the other verifier grants no access here.
	foreignBytes := make([]byte, 32)
	foreignBytes[0] = 1
	foreignSecret := base64.RawURLEncoding.EncodeToString(foreignBytes)
	hash := sha256.Sum256([]byte(foreignSecret))
	cfg.Issuer = "https://foreign-project.example.test"
	cfg.Introspection = &projectnative.ProjectIntrospectionConfig{Clients: []tokenservice.IntrospectionClientConfig{{ID: tokenConsumerID, SecretHashes: []string{hex.EncodeToString(hash[:])}, Audiences: []string{"reports"}}}, ConsumerPerMinute: 100, ProjectPerMinute: 100}
	other, err := projectnative.NewProjectTokens(ctx, f.key, cfg, projectnative.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, IssuanceRedis: issuanceRedis, Hash: f.hash})
	require.NoError(t, err)
	foreign, ok := other.Authenticate(tokenConsumerID, tokenConsumerSecret)
	require.False(t, ok)
	require.Nil(t, foreign)
	foreign, ok = other.Authenticate(tokenConsumerID, foreignSecret)
	require.True(t, ok)
	rejected, ok := service.Authenticate(tokenConsumerID, foreignSecret)
	require.False(t, ok)
	require.Nil(t, rejected)
	invalid, err = service.Inspect(ctx, foreign, raw)
	require.ErrorIs(t, err, tokendomain.ErrForbidden)
	require.Equal(t, tokenservice.IntrospectionResult{}, invalid)
	foreignToken, err := other.Exchange(ctx, input)
	require.NoError(t, err)
	invalid, err = service.Inspect(ctx, consumer, foreignToken.Raw)
	require.NoError(t, err)
	require.Equal(t, tokenservice.IntrospectionResult{}, invalid, "foreign issuer must not reach online authority")
}
