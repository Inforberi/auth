package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func projectSMTPDrill(t *testing.T, admin *pgx.Conn, reader *catalog.RuntimeCredentialReader, key projectruntime.Key, registry *projectruntime.Registry) {
	t.Helper()
	ctx := t.Context()
	cfg := admin.Config().Copy()
	var err error
	cfg.Database, _, err = (projectdomain.PreparationReservation{ProjectID: key.Binding.ProjectID, ReservationID: key.Binding.ReservationID}).ResourceNames()
	require.NoError(t, err)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close(context.WithoutCancel(ctx))) })
	_, err = db.Exec(ctx, `CREATE TEMP TABLE smtp_before AS TABLE auth.smtp_settings; DELETE FROM auth.smtp_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings SELECT * FROM smtp_before`)
		require.NoError(t, err)
	})
	addr := os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR")
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_PASSWORD"), DB: 15})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	beforeRedis, err := rdb.DBSize(ctx).Result()
	require.NoError(t, err)
	require.Zero(t, beforeRedis)
	deps := appauth.ProjectSMTPDependencies{Registry: registry, Reader: reader, Redis: rdb}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	allowed := []string{listener.Addr().String()}
	mail, err := appauth.NewProjectMailer(ctx, key, allowed, deps)
	require.ErrorIs(t, err, settingsdomain.ErrNotInitialized)
	require.Nil(t, mail)
	var count int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.smtp_settings`).Scan(&count))
	require.Zero(t, count, "missing project SMTP must never be initialized from ENV")
	configuration, err := reader.LoadAuthConfiguration(ctx, key, registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("smtp-settings:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	smtpHost, smtpPort, err := net.SplitHostPort(allowed[0])
	require.NoError(t, err)
	port, err := strconv.Atoi(smtpPort)
	require.NoError(t, err)
	input := settingsdomain.SMTPConfig{Host: smtpHost, Port: port, Username: "fixture", From: "auth@example.test", Domain: "example.test", RequireTLS: true}
	seed, err := settingsservice.NewSMTPSeed(input, "runtime-smtp-fixture-only", allowed, true, cipher)
	require.NoError(t, err)
	encoded, err := json.Marshal(input)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.smtp_settings(singleton,configuration,password_set,password) VALUES(true,$1::jsonb,true,$2)`, string(encoded), seed.Password)
	require.NoError(t, err)
	var xmin string
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text FROM auth.smtp_settings`).Scan(&xmin))
	mail, err = appauth.NewProjectMailer(ctx, key, allowed, deps)
	require.NoError(t, err)
	allowed[0] = "forbidden.example.test:587"
	connected, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	t.Cleanup(func() { close(release) })
	go projectSMTPGreeting(ctx, listener, connected, release, finished)
	sent := make(chan error, 1)
	go func() { sent <- mail.SendContext(ctx, "user@example.test", "fixture", "synthetic body") }()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("project SMTP did not reach the selected server")
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	err = registry.UsePool(probe, key, func(ctx context.Context, pool *pgxpool.Pool) error {
		var one int
		return pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
	})
	cancel()
	require.NoError(t, err, "single-connection pool must be free during SMTP I/O")
	release <- struct{}{}
	require.ErrorContains(t, <-sent, "SMTP requires STARTTLS")
	require.NoError(t, <-finished, "no AUTH, recipient or message may precede TLS")
	var afterXmin string
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text FROM auth.smtp_settings`).Scan(&afterXmin))
	require.Equal(t, xmin, afterXmin, "construction and sending must not write settings")
	for _, test := range []struct{ name, sql string }{
		{"updated target outside allowlist", `UPDATE auth.smtp_settings SET configuration=jsonb_set(configuration,'{host}','"forbidden.example.test"')`},
		{"updated settings disable TLS", `UPDATE auth.smtp_settings SET configuration=jsonb_set(configuration,'{requireTls}','false')`},
		{"corrupted encrypted password", `UPDATE auth.smtp_settings SET password=set_byte(password,octet_length(password)-1,get_byte(password,octet_length(password)-1)#1)`},
		{"settings deleted after construction", `DELETE FROM auth.smtp_settings`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := db.Exec(ctx, test.sql)
			require.NoError(t, err)
			require.ErrorContains(t, mail.SendContext(ctx, "user@example.test", "fixture", "synthetic body"), "SMTP configuration unavailable")
			_, err = db.Exec(ctx, `DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings(singleton,configuration,password_set,password) VALUES(true,$1::jsonb,true,$2)`, string(encoded), seed.Password)
			require.NoError(t, err)
		})
	}
	t.Run("project email scenarios and delivery", func(t *testing.T) { projectEmailDrill(t, admin, db, rdb, key, deps, listener) })
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := admin.Exec(context.WithoutCancel(ctx), `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, key.Binding.ProjectID, key.Version)
		require.NoError(t, err)
	})
	require.ErrorContains(t, mail.SendContext(ctx, "user@example.test", "fixture", "synthetic body"), "SMTP configuration unavailable")
	countRedis, err := rdb.DBSize(ctx).Result()
	require.NoError(t, err)
	require.Equal(t, beforeRedis, countRedis, "credential reads must not consume administrative probe limits")
}

func projectSMTPGreeting(ctx context.Context, listener net.Listener, connected chan<- struct{}, release <-chan struct{}, finished chan<- error) {
	conn, err := listener.Accept()
	if err != nil {
		finished <- err
		return
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		finished <- err
		return
	}
	close(connected)
	select {
	case <-release:
	case <-ctx.Done():
		finished <- ctx.Err()
		return
	}
	if _, err := fmt.Fprint(conn, "220 fixture SMTP\r\n"); err != nil {
		finished <- err
		return
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "EHLO ") {
		finished <- fmt.Errorf("unexpected greeting %q: %w", line, err)
		return
	}
	if _, err := fmt.Fprint(conn, "250 fixture\r\n"); err != nil {
		finished <- err
		return
	}
	line, err = reader.ReadString('\n')
	if line != "" || err == nil {
		finished <- fmt.Errorf("SMTP command sent before TLS: %q", line)
		return
	}
	finished <- nil
}
