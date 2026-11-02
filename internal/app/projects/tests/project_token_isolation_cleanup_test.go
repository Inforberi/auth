package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func (f tokenIsolationFixture) registerCleanup(t *testing.T, ctx context.Context) {
	t.Helper()
	for i, key := range f.projects.projects {
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		configuration, err := f.projects.deps.Reader.LoadAuthConfiguration(ctx, key, f.projects.deps.Registry)
		require.NoError(t, err)
		purpose, err := scope.Purpose("jwt-issuance-limits:v1")
		require.NoError(t, err)
		cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		prefix, err := scope.RedisPrefix("jwt-issuance", "auth:{jwt-issuance}:")
		require.NoError(t, err)
		lookup, err := scope.RedisPrefix("jwt-refresh-lookup", "auth:{jwt-refresh-lookup}:")
		require.NoError(t, err)
		introspection, err := scope.RedisPrefix("jwt-introspection", "auth:{jwt-introspection}:")
		require.NoError(t, err)
		for _, name := range []string{prefix + "project", prefix + "ip:" + cipher.Digest("127.0.0.1"), prefix + "actor:" + cipher.Digest(httpIsolationUser), lookup + "project", lookup + "ip:" + cipher.Digest("127.0.0.1"), introspection + "project", introspection + "client:" + cipher.Digest(isolationTokenClient)} {
			f.projects.redisKeys[name] = struct{}{}
		}
		db := f.projects.databases[i]
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			rows, err := db.Query(cleanup, `SELECT id::text FROM auth.sessions WHERE user_id=$1`, httpIsolationUser)
			require.NoError(t, err)
			for rows.Next() {
				var id string
				require.NoError(t, rows.Scan(&id))
				f.projects.redisKeys[prefix+"session:"+cipher.Digest(id)] = struct{}{}
			}
			require.NoError(t, rows.Err())
			rows.Close()
			for _, table := range []string{"token_issuance_audit", "refresh_audit"} {
				_, err := db.Exec(cleanup, `DELETE FROM auth.`+table+` WHERE user_id=$1`, httpIsolationUser)
				require.NoError(t, err)
			}
			_, err = db.Exec(cleanup, `DELETE FROM auth.refresh_tokens WHERE session_id IN(SELECT id FROM auth.sessions WHERE user_id=$1)`, httpIsolationUser)
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `DELETE FROM auth.user_roles WHERE role_id IN(SELECT id FROM auth.roles WHERE key='http_token_isolation');
 DELETE FROM auth.roles WHERE key='http_token_isolation'`)
			require.NoError(t, err)
		})
	}
}
