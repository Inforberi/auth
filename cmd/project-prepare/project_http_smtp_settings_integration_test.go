package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func (f projectAccountFixture) httpSMTPSettings(t *testing.T, ctx context.Context, web projectAccountRequest, origin, actorToken, ordinaryToken string) {
	t.Helper()
	const actor = "f8300000-0000-4000-8000-000000000001"
	const path = "/api/v1/admin/auth/settings/smtp"
	_, err := f.db.Exec(ctx, `CREATE TEMP TABLE smtp_http_before AS TABLE auth.smtp_settings`)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(f.key.Binding.ProjectID))
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("smtp-test-limit", "auth:settings:smtp-test:")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.smtp_settings_audit WHERE actor_id=$1;
 DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings SELECT * FROM smtp_http_before`, actor)
		require.NoError(t, err)
		require.NoError(t, f.rdb.Del(cleanup, prefix+"user:"+actor, prefix+"project").Err())
	})
	read := func(cookie string, expected int) settingshttp.SMTPResponse {
		t.Helper()
		status, cookies, body := web("GET", path, origin, cookie, "")
		require.Equal(t, expected, status, "%s", body)
		require.Empty(t, cookies)
		require.NotContains(t, string(body), "runtime-smtp-fixture-only")
		require.NotContains(t, string(body), "new-project-SMTP-secret")
		var response settingshttp.SMTPResponse
		if expected == 200 {
			require.NoError(t, json.Unmarshal(body, &response))
		}
		return response
	}
	read("", 401)
	read(ordinaryToken, 403)
	before := read(actorToken, 200)
	tls := true
	config := &settingshttp.SMTPConfigRequest{Host: before.Config.Host, Port: before.Config.Port, Username: before.Config.Username, From: before.Config.From, Domain: before.Config.Domain, RequireTLS: &tls}
	password := "new-project-SMTP-secret"
	input := settingshttp.SMTPUpdateRequest{ExpectedVersion: before.Version, Config: config, Password: &password}
	web.command(t, path, "https://foreign.example.test", actorToken, input, 403, nil)
	web.command(t, path, origin, ordinaryToken, input, 403, nil)
	invalidConfig := *config
	invalidConfig.Host = "169.254.169.254"
	invalid := input
	invalid.Config = &invalidConfig
	web.command(t, path, origin, actorToken, invalid, 400, nil)
	noTLS := false
	invalidConfig = *config
	invalidConfig.RequireTLS = &noTLS
	web.command(t, path, origin, actorToken, invalid, 400, nil)
	var changed settingshttp.SMTPResponse
	web.command(t, path, origin, actorToken, input, 200, &changed)
	require.Equal(t, before.Version+1, changed.Version)
	require.True(t, changed.PasswordSet)
	web.command(t, path, origin, actorToken, input, 409, nil)
	var encrypted, retained []byte
	require.NoError(t, f.db.QueryRow(ctx, `SELECT password FROM auth.smtp_settings`).Scan(&encrypted))
	require.NotEqual(t, []byte(password), encrypted)
	input.ExpectedVersion, input.Password = changed.Version, nil
	input.Config.From = "updated@example.test"
	web.command(t, path, origin, actorToken, input, 200, &changed)
	require.Equal(t, before.Version+2, changed.Version)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT password FROM auth.smtp_settings`).Scan(&retained))
	require.Equal(t, encrypted, retained, "omitted password must preserve the ciphertext")
	input.ExpectedVersion = changed.Version
	web.command(t, path, origin, actorToken, input, 200, &changed)
	require.Equal(t, before.Version+2, changed.Version)
	read(actorToken, 200)
	web.command(t, path+"/test", origin, actorToken, settingshttp.SMTPTestRequest{ExpectedVersion: before.Version}, 409, nil)
	connected, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	running, stop := context.WithCancel(ctx)
	defer stop()
	go projectSMTPGreeting(running, f.listener, connected, release, finished)
	done := make(chan struct{})
	var status int
	var body []byte
	go func() {
		defer close(done)
		encoded, err := json.Marshal(settingshttp.SMTPTestRequest{ExpectedVersion: changed.Version})
		if err != nil {
			return
		}
		status, _, body = web("POST", path+"/test", origin, actorToken, string(encoded))
	}()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("SMTP HTTP test did not reach the saved server")
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	err = f.deps.Registry.UsePool(probe, f.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		var version int64
		return pool.QueryRow(ctx, `SELECT version FROM auth.smtp_settings WHERE singleton FOR UPDATE NOWAIT`).Scan(&version)
	})
	cancel()
	close(release)
	require.NoError(t, err, "SMTP probe must not retain the runtime lease or SQL row lock")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("SMTP HTTP probe did not drain")
	}
	require.Equal(t, 409, status, "%s", body)
	require.Contains(t, string(body), `"code":"smtp_connection_failed"`)
	require.NoError(t, <-finished, "no AUTH or message may precede TLS")
	require.NoError(t, f.rdb.Set(ctx, prefix+"user:"+actor, 3, time.Minute).Err())
	web.command(t, path+"/test", origin, actorToken, settingshttp.SMTPTestRequest{ExpectedVersion: changed.Version}, 429, nil)
	var audits int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.smtp_settings_audit WHERE actor_id=$1`, actor).Scan(&audits))
	require.Equal(t, 2, audits)
	_, err = f.db.Exec(ctx, `DELETE FROM auth.smtp_settings`)
	require.NoError(t, err)
	read(actorToken, 403)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.smtp_settings`).Scan(&audits))
	require.Zero(t, audits, "reading missing SMTP must not initialize credentials")
}
