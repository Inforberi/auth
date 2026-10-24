package runtime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
)

func TestTrustedTargetTransport(t *testing.T) {
	for _, tc := range []struct {
		host string
		tls  *tls.Config
	}{
		{"db.example", nil},
		{"db.example", &tls.Config{ServerName: "db.example", InsecureSkipVerify: true}},
		{"db.example", &tls.Config{ServerName: "other.example"}},
		{"db.example,other", &tls.Config{}},
		{"/tmp/../var", nil},
		{"/var/run/postgresql", &tls.Config{}},
	} {
		_, err := NewTarget(tc.host, 5432, tc.tls)
		require.Error(t, err)
	}
	transport := &tls.Config{ServerName: "db.example"}
	target, err := NewTarget("db.example", 5432, transport)
	require.NoError(t, err)
	transport.ServerName = "changed.example"
	require.Equal(t, "db.example", target.tls.ServerName)
	require.Equal(t, uint16(tls.VersionTLS12), target.tls.MinVersion)
	_, err = NewTarget("/var/run/postgresql", 5432, nil)
	require.NoError(t, err)
}

func testCredential(t *testing.T, key Key) credentials.DatabaseCredential {
	t.Helper()
	codec, err := credentials.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), "root-1")
	require.NoError(t, err)
	sealed, err := codec.Generate(key.Binding)
	require.NoError(t, err)
	value, err := codec.OpenDatabase(key.Binding, credentials.Version, codec.KeyID(), sealed)
	require.NoError(t, err)
	return value
}

func TestPoolConfigDoesNotInheritProjectOrBudgetFromEnvironment(t *testing.T) {
	t.Setenv("PGHOST", "attacker.example")
	t.Setenv("PGDATABASE", "other_database")
	t.Setenv("PGUSER", "root")
	t.Setenv("PGPASSWORD", "environment-secret")
	t.Setenv("PGOPTIONS", "-c search_path=public -c statement_timeout=0")
	target, err := NewTarget("db.example", 5433, &tls.Config{ServerName: "db.example"})
	require.NoError(t, err)
	value := testCredential(t, testKey())
	cfg, err := poolConfig(testConfig(), target, value)
	require.NoError(t, err)
	c := cfg.ConnConfig
	require.Equal(t, "db.example", c.Host)
	require.Equal(t, uint16(5433), c.Port)
	require.Equal(t, "authp_a2000000000040008000000000000001", c.Database)
	require.Equal(t, "authr_a2000000000040008000000000000001", c.User)
	require.Equal(t, value.Password(), c.Password)
	require.Empty(t, c.Fallbacks)
	require.Equal(t, "scram-sha-256", c.RequireAuth)
	require.Equal(t, "db.example", c.TLSConfig.ServerName)
	require.False(t, c.TLSConfig.InsecureSkipVerify)
	require.NotContains(t, c.RuntimeParams, "options")
	require.NotContains(t, c.RuntimeParams, "search_path")
	require.Equal(t, "3000", c.RuntimeParams["statement_timeout"])
	require.EqualValues(t, 1, cfg.MaxConns)
	require.Zero(t, cfg.MinConns)
	require.Zero(t, cfg.MinIdleConns)
}

type credentialLoaderFunc func(context.Context, Key) (credentials.DatabaseCredential, error)

func (f credentialLoaderFunc) LoadDatabaseCredential(ctx context.Context, key Key) (credentials.DatabaseCredential, error) {
	return f(ctx, key)
}

func TestRegistryRejectsUnknownTargetAndMismatchedCredential(t *testing.T) {
	target, err := NewTarget("/var/run/postgresql", 5432, nil)
	require.NoError(t, err)
	var reads int
	other := testKey()
	other.Binding.DatabaseOID++
	value := testCredential(t, other)
	r, err := New(testConfig(), map[string]Target{"primary": target}, credentialLoaderFunc(func(context.Context, Key) (credentials.DatabaseCredential, error) {
		reads++
		return value, nil
	}), func(context.Context, *pgx.Conn, credentials.Binding) error { t.Error("must not connect"); return nil })
	require.NoError(t, err)
	cleanupRegistry(t, r)
	key := testKey()
	key.Binding.StorageTarget = "unknown"
	require.ErrorIs(t, r.Use(t.Context(), key, func(context.Context, Database) error { return nil }), ErrUnavailable)
	require.Zero(t, reads)
	require.ErrorIs(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }), ErrUnavailable)
	require.Equal(t, 1, reads)
}

func TestRegistryRejectsInvalidBudgets(t *testing.T) {
	cfg := testConfig()
	require.True(t, cfg.Valid())
	cfg.MaxRuntimes = 2
	require.False(t, cfg.Valid())
	cfg.MaxRuntimes = 1
	cfg.ConnectionsPerProject = 0
	require.False(t, cfg.Valid())
	cfg = testConfig()
	cfg.MaxAcquiring = 0
	require.False(t, cfg.Valid())
}
