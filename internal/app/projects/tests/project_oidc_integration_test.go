package projects_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	oidcdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	oidcredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/repository/redis"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func projectOIDCDrill(t *testing.T, ctx context.Context, admin, db *pgx.Conn, rdb *redis.Client, key projectruntime.Key, deps projectapp.ProjectSMTPDependencies, sourceUser string, hash *hasher.Bounded) {
	t.Helper()
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	_, err = db.Exec(ctx, `CREATE TEMP TABLE oidc_policy_before AS TABLE auth.auth_settings; CREATE TEMP TABLE oidc_providers_before AS TABLE auth.provider_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM oidc_policy_before; DELETE FROM auth.provider_settings; INSERT INTO auth.provider_settings SELECT * FROM oidc_providers_before`)
		require.NoError(t, err)
	})
	owners := projectmethods.NewProjectOIDCClients(ctx)
	t.Cleanup(owners.Close)
	oidcDeps := projectmethods.ProjectOIDCDependencies{Registry: deps.Registry, Reader: deps.Reader, Redis: rdb, Clients: owners}
	services := map[string]*projectmethods.ProjectOIDC{}
	ciphers := map[string]*secretbox.Cipher{}
	prefixes := map[string]string{}
	keys := []string{}
	const ip = "192.0.2.85"
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if len(keys) > 0 {
			require.NoError(t, rdb.Del(cleanup, keys...).Err())
		}
	})
	for _, name := range []string{"google", "telegram"} {
		purpose, err := scope.Purpose("provider-" + name + ":v1")
		require.NoError(t, err)
		cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		encrypted, err := cipher.Seal([]byte("synthetic-project-oidc-secret"))
		require.NoError(t, err)
		id := "project-oidc.apps.googleusercontent.com"
		if name == "telegram" {
			id = "123456789"
		}
		_, err = db.Exec(ctx, `INSERT INTO auth.provider_settings(provider,version,client_id,secret,secret_set) VALUES($1,1,$2,$3,true)
 ON CONFLICT(provider) DO UPDATE SET version=auth.provider_settings.version+1,client_id=EXCLUDED.client_id,secret=EXCLUDED.secret,secret_set=true`, name, id, encrypted)
		require.NoError(t, err)
		purpose, err = scope.Purpose(name + "-login:v1")
		require.NoError(t, err)
		ciphers[name], err = secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		prefix, err := scope.RedisPrefix("oidc-"+name, "auth:"+name)
		require.NoError(t, err)
		prefixes[name] = strings.TrimSuffix(prefix, ":")
		keys = append(keys, prefixes[name]+":limit:"+ciphers[name].Digest(ip), prefixes[name]+":limit:global")
		services[name], err = projectmethods.NewProjectOIDC(ctx, key, projectmethods.ProjectOIDCConfig{Provider: name, Enabled: true, RedirectURI: "https://project-oidc.example.test/api/v1/auth/" + name + "/callback", IPLimit: 30, GlobalLimit: 1000, Session: projectPasswordFixtureConfig().Session, Timeout: 10 * time.Second}, oidcDeps)
		require.NoError(t, err)
	}
	_, err = db.Exec(ctx, `UPDATE auth.auth_settings SET google_enabled=true,telegram_enabled=true`)
	require.NoError(t, err)
	var before int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions`).Scan(&before))
	for _, name := range []string{"google", "telegram"} {
		started, err := services[name].Start(ctx, ip)
		require.NoError(t, err)
		parsed, err := url.Parse(started.URL)
		require.NoError(t, err)
		expectedID := "project-oidc.apps.googleusercontent.com"
		if name == "telegram" {
			expectedID = "123456789"
		}
		require.Equal(t, expectedID, parsed.Query().Get("client_id"))
		state := parsed.Query().Get("state")
		require.Len(t, state, 43)
		require.Equal(t, "https://project-oidc.example.test/api/v1/auth/"+name+"/callback", parsed.Query().Get("redirect_uri"))
		require.Equal(t, "S256", parsed.Query().Get("code_challenge_method"))
		require.NotEmpty(t, parsed.Query().Get("nonce"))
		require.Len(t, started.Binding, 43)
		keys = append(keys, prefixes[name]+":flow:"+ciphers[name].Digest(state))
		input := oidcservice.CallbackInput{Code: "synthetic-unused-code", State: state, Binding: started.Binding, IP: ip}
		wrong := input
		wrong.Binding = strings.Repeat("A", 43)
		rejected, err := services[name].Callback(ctx, wrong)
		require.ErrorIs(t, err, oidcdomain.ErrInvalidFlow)
		require.Nil(t, rejected)
		other := "google"
		if name == "google" {
			other = "telegram"
		}
		rejected, err = services[other].Callback(ctx, input)
		require.ErrorIs(t, err, oidcdomain.ErrInvalidFlow)
		require.Nil(t, rejected)
		foreign, err := realmscope.New("project", "f8500000-0000-4000-8000-000000000001")
		require.NoError(t, err)
		purpose, err := foreign.Purpose(name + "-login:v1")
		require.NoError(t, err)
		cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		flows, err := oidcredis.NewScoped(rdb, cipher, name, foreign)
		require.NoError(t, err)
		consumed, err := flows.Consume(ctx, state, started.Binding)
		require.ErrorIs(t, err, oidcdomain.ErrInvalidFlow)
		require.Nil(t, consumed)
		// Changed provider revision rejects before exchange, so this fixture needs no external network.
		nextID := "project-oidc-next.apps.googleusercontent.com"
		if name == "telegram" {
			nextID = "123456790"
		}
		_, err = db.Exec(ctx, `UPDATE auth.provider_settings SET version=version+1,client_id=$2 WHERE provider=$1`, name, nextID)
		require.NoError(t, err)
		rejected, err = services[name].Callback(ctx, input)
		require.ErrorIs(t, err, oidcdomain.ErrInvalidFlow)
		require.Nil(t, rejected)
		rejected, err = services[name].Callback(ctx, input)
		require.ErrorIs(t, err, oidcdomain.ErrInvalidFlow)
		require.Nil(t, rejected)
		fresh, err := services[name].Start(ctx, ip)
		require.NoError(t, err)
		freshURL, err := url.Parse(fresh.URL)
		require.NoError(t, err)
		require.Equal(t, nextID, freshURL.Query().Get("client_id"))
		keys = append(keys, prefixes[name]+":flow:"+ciphers[name].Digest(freshURL.Query().Get("state")))
	}
	_, err = db.Exec(ctx, `UPDATE auth.auth_settings SET google_enabled=false,telegram_enabled=false`)
	require.NoError(t, err)
	for _, name := range []string{"google", "telegram"} {
		started, err := services[name].Start(ctx, ip)
		require.ErrorIs(t, err, settingsdomain.ErrMethodDisabled)
		require.Nil(t, started)
	}
	t.Run("project identity HTTP", func(t *testing.T) {
		(projectIdentityHTTPFixture{admin: admin, db: db, rdb: rdb, key: key, deps: deps, clients: owners, ciphers: ciphers, prefixes: prefixes, keys: &keys, sourceUser: sourceUser, hash: hash}).run(t, ctx)
	})
	var after int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions`).Scan(&after))
	require.Equal(t, before, after)
}
