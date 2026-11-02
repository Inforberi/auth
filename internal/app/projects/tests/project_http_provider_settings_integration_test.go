package projects_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func (f projectAccountFixture) httpProviderSettings(t *testing.T, ctx context.Context, web projectAccountRequest, origin, actorToken, ordinaryToken string) {
	t.Helper()
	const actor = "f8300000-0000-4000-8000-000000000001"
	const base = "/api/v1/admin/auth/settings/providers/"
	_, err := f.db.Exec(ctx, `CREATE TEMP TABLE provider_http_before AS TABLE auth.provider_settings; DELETE FROM auth.provider_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.provider_settings_audit WHERE actor_id=$1;
 DELETE FROM auth.provider_settings; INSERT INTO auth.provider_settings SELECT * FROM provider_http_before`, actor)
		require.NoError(t, err)
	})
	configuration, err := f.deps.Reader.LoadAuthConfiguration(ctx, f.key, f.deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(f.key.Binding.ProjectID))
	require.NoError(t, err)
	ciphers := make(map[string]*secretbox.Cipher)
	for _, name := range []string{"google", "telegram"} {
		purpose, err := scope.Purpose("provider-" + name + ":v1")
		require.NoError(t, err)
		cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		ciphers[name] = cipher
		encrypted, err := cipher.Seal([]byte("old-project-provider-secret"))
		require.NoError(t, err)
		id := "project-settings.apps.googleusercontent.com"
		if name == "telegram" {
			id = "741852963"
		}
		_, err = f.db.Exec(ctx, `INSERT INTO auth.provider_settings(provider,client_id,secret,secret_set) VALUES($1,$2,$3,true)`, name, id, encrypted)
		require.NoError(t, err)
	}
	read := func(name, cookie string, expected int) settingshttp.ProviderResponse {
		t.Helper()
		status, cookies, body := web("GET", base+name, origin, cookie, "")
		require.Equal(t, expected, status, "%s", body)
		require.Empty(t, cookies)
		require.NotContains(t, string(body), "project-provider-secret")
		var response settingshttp.ProviderResponse
		if expected == 200 {
			require.NoError(t, json.Unmarshal(body, &response))
		}
		return response
	}
	read("google", "", 401)
	read("google", ordinaryToken, 403)
	read("github", actorToken, 400)
	for _, name := range []string{"google", "telegram"} {
		before := read(name, actorToken, 200)
		secret := "new-" + name + "-project-provider-secret"
		id := before.ClientID
		input := settingshttp.ProviderUpdateRequest{ExpectedVersion: before.Version, ClientID: &id, Secret: &secret}
		web.command(t, base+name, "https://foreign.example.test", actorToken, input, 403, nil)
		web.command(t, base+name, origin, ordinaryToken, input, 403, nil)
		var changed settingshttp.ProviderResponse
		body := web.commandMethod(t, "POST", base+name, origin, actorToken, input, 200, &changed)
		require.NotContains(t, string(body), secret)
		require.True(t, changed.SecretSet)
		require.Equal(t, before.Version+1, changed.Version)
		web.command(t, base+name, origin, actorToken, input, 409, nil)
		var encrypted, preserved []byte
		require.NoError(t, f.db.QueryRow(ctx, `SELECT secret FROM auth.provider_settings WHERE provider=$1`, name).Scan(&encrypted))
		require.NotEqual(t, []byte(secret), encrypted)
		err := f.deps.Registry.UsePool(ctx, f.key, func(ctx context.Context, pool *pgxpool.Pool) error {
			providers := settingsservice.NewProviders(settingspostgres.New(pool), ciphers["google"], ciphers["telegram"])
			_, plain, err := providers.Credentials(ctx, name)
			if err == nil {
				require.Equal(t, secret, plain)
			}
			return err
		})
		require.NoError(t, err, "OIDC runtime must be able to decrypt the project-scoped update")
		input.ExpectedVersion, input.Secret = changed.Version, nil
		web.command(t, base+name, origin, actorToken, input, 200, &changed)
		require.Equal(t, before.Version+1, changed.Version)
		require.NoError(t, f.db.QueryRow(ctx, `SELECT secret FROM auth.provider_settings WHERE provider=$1`, name).Scan(&preserved))
		require.Equal(t, encrypted, preserved)
		read(name, actorToken, 200)
	}
	google := read("google", actorToken, 200)
	changedID, secret := "other-project.apps.googleusercontent.com", "replacement-project-provider-secret"
	web.command(t, base+"google", origin, actorToken, settingshttp.ProviderUpdateRequest{ExpectedVersion: google.Version, ClientID: &changedID, Secret: &secret}, 409, nil)
	status, _, _ := web("GET", "/api/v1/auth/me", origin, ordinaryToken, "")
	require.Equal(t, 200, status, "provider rotation must not revoke an existing session")
	var audits int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.provider_settings_audit WHERE actor_id=$1`, actor).Scan(&audits))
	require.Equal(t, 2, audits, "failed and no-op changes must not add audit rows")
	_, err = f.db.Exec(ctx, `DELETE FROM auth.provider_settings WHERE provider='telegram'`)
	require.NoError(t, err)
	read("telegram", actorToken, 403)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.provider_settings WHERE provider='telegram'`).Scan(&audits))
	require.Zero(t, audits, "metadata read must not initialize a provider from ENV")
}
