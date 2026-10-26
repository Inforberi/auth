package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

const (
	passwordFixtureUser  = "f8100000-0000-4000-8000-000000000001"
	passwordFixtureEmail = "runtime-password@example.test"
)

func projectPasswordDrill(t *testing.T, admin *pgx.Conn, reader *catalog.RuntimeCredentialReader, key projectruntime.Key, registry *projectruntime.Registry) {
	t.Helper()
	ctx := t.Context()
	addr := os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR")
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err, "actual project password SQL test requires explicit isolated RedisDB15")
	require.Equal(t, "127.0.0.1", host, "refusing non-loopback password fixture")
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_PASSWORD"), DB: 15})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	count, err := rdb.DBSize(ctx).Result()
	require.NoError(t, err)
	require.Zero(t, count, "dedicated RedisDB15 must be empty")
	cfg := admin.Config().Copy()
	cfg.Database, _, err = (projectdomain.PreparationReservation{ProjectID: key.Binding.ProjectID, ReservationID: key.Binding.ReservationID}).ResourceNames()
	require.NoError(t, err)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, db.Close(cleanup))
	})
	var clean bool
	require.NoError(t, db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.users WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM auth.roles WHERE key='project_password_fixture_mfa')`, passwordFixtureUser).Scan(&clean))
	require.True(t, clean)
	_, err = db.Exec(ctx, `CREATE TEMP TABLE password_policy_before AS TABLE auth.auth_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.sessions WHERE user_id=$1;
   DELETE FROM auth.users WHERE id=$1; DELETE FROM auth.roles WHERE key='project_password_fixture_mfa';
   DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM password_policy_before`, passwordFixtureUser)
		require.NoError(t, err)
	})
	realHash := hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32)
	bounded := hasher.NewBounded(realHash, 1)
	const password = "Synthetic-runtime-password-72!"
	encoded, err := bounded.GenerateHash(ctx, []byte(password))
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1);
 INSERT INTO auth.user_emails(id,user_id,email,verified_at) VALUES('f8100000-0000-4000-8000-000000000002',$1,$2,clock_timestamp());
 INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES($1,'f8100000-0000-4000-8000-000000000002',$3)`, passwordFixtureUser, passwordFixtureEmail, encoded)
	require.NoError(t, err)
	input := passwordservice.LoginInput{Email: passwordFixtureEmail, Password: password, UserAgent: "project runtime fixture", IP: "192.0.2.71"}
	configuration, err := reader.LoadAuthConfiguration(ctx, key, registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("password-reset:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
	require.NoError(t, err)
	keys := []string{prefix + cipher.Digest("login-ip:"+input.IP), prefix + cipher.Digest("login-email:"+input.Email), prefix + cipher.Digest("login-global")}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, rdb.Del(cleanup, keys...).Err())
		count, err := rdb.DBSize(cleanup).Result()
		require.NoError(t, err)
		require.Zero(t, count)
	})
	pcfg := projectPasswordFixtureConfig()
	deps := appauth.ProjectPasswordDependencies{Registry: registry, Reader: reader, Redis: rdb, Hash: bounded}
	svc, err := appauth.NewProjectPassword(ctx, key, pcfg, deps)
	require.NoError(t, err)
	first, err := svc.Login(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotEmpty(t, first.Token)
	require.Equal(t, accountdomain.UserID(passwordFixtureUser), first.UserID)
	var stored bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions WHERE token_hash=$1 AND user_id=$2 AND primary_method='password')`, tokengenerate.New().Hash(first.Token), passwordFixtureUser).Scan(&stored))
	require.True(t, stored)
	sessions := func() int {
		var n int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, passwordFixtureUser).Scan(&n))
		return n
	}
	t.Run("wrong password creates no session", func(t *testing.T) {
		before := sessions()
		bad := input
		bad.Password = "Wrong-synthetic-password-72!"
		result, err := svc.Login(ctx, bad)
		require.ErrorIs(t, err, passworddomain.ErrInvalidEmailOrPassword)
		require.Nil(t, result)
		require.Equal(t, before, sessions())
	})
	t.Run("disabled method creates no session", func(t *testing.T) {
		_, err := db.Exec(ctx, `UPDATE auth.auth_settings SET password_enabled=false`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `UPDATE auth.auth_settings SET password_enabled=true`)
			require.NoError(t, err)
		})
		before := sessions()
		result, err := svc.Login(ctx, input)
		require.ErrorIs(t, err, settingsdomain.ErrMethodDisabled)
		require.Nil(t, result)
		require.Equal(t, before, sessions())
	})
	t.Run("required email verification", func(t *testing.T) {
		_, err := db.Exec(ctx, `UPDATE auth.auth_settings SET password_email_verification='required'; UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, passwordFixtureUser)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `UPDATE auth.auth_settings SET password_email_verification='disabled'; UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, passwordFixtureUser)
			require.NoError(t, err)
		})
		before := sessions()
		result, err := svc.Login(ctx, input)
		require.ErrorIs(t, err, accountdomain.ErrEmailUnverified)
		require.Nil(t, result)
		require.Equal(t, before, sessions())
	})
	t.Run("blocked user", func(t *testing.T) {
		_, err := db.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, passwordFixtureUser)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `UPDATE auth.users SET status='active' WHERE id=$1`, passwordFixtureUser)
			require.NoError(t, err)
		})
		before := sessions()
		result, err := svc.Login(ctx, input)
		require.Error(t, err)
		require.Nil(t, result)
		require.Equal(t, before, sessions())
	})
	t.Run("enrolled MFA cannot be bypassed", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,decode(repeat('11',64),'hex'),0)`, passwordFixtureUser)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `DELETE FROM auth.mfa_totp WHERE user_id=$1`, passwordFixtureUser)
			require.NoError(t, err)
		})
		before := sessions()
		result, err := svc.Login(ctx, input)
		require.ErrorIs(t, err, sessiondomain.ErrMFARequired)
		require.Nil(t, result)
		require.Equal(t, before, sessions())
	})
	t.Run("role required MFA cannot be bypassed", func(t *testing.T) {
		_, err := db.Exec(ctx, `WITH r AS (INSERT INTO auth.roles(key,name,mfa_required) VALUES('project_password_fixture_mfa','Fixture MFA',true) RETURNING id) INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, passwordFixtureUser)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id IN (SELECT id FROM auth.roles WHERE key='project_password_fixture_mfa'); DELETE FROM auth.roles WHERE key='project_password_fixture_mfa'`, passwordFixtureUser)
			require.NoError(t, err)
		})
		before := sessions()
		result, err := svc.Login(ctx, input)
		require.ErrorIs(t, err, sessiondomain.ErrMFARequired)
		require.Nil(t, result)
		require.Equal(t, before, sessions())
	})
	for _, suspend := range []bool{false, true} {
		name := "hash work holds no SQL connection"
		if suspend {
			name = "suspend during hash never discloses token"
		}
		t.Run(name, func(t *testing.T) {
			projectPasswordHashDrill(t, admin, key, registry, pcfg, deps, realHash, input, suspend)
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	before := sessions()
	result, err := svc.Login(canceled, input)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, before, sessions())
	t.Run("project registration", func(t *testing.T) { projectRegistrationDrill(t, admin, db, rdb, key, pcfg, deps) })
	t.Run("project MFA management HTTP", func(t *testing.T) { projectMFAManagementHTTPDrill(t, admin, db, rdb, key, pcfg, deps, input) })
	t.Run("project MFA login", func(t *testing.T) { projectMFADrill(t, admin, db, rdb, key, pcfg, deps, input) })
	count, err = rdb.DBSize(ctx).Result()
	require.NoError(t, err)
	require.EqualValues(t, 3, count)
}

// Native Argon2 work is deliberately paused; no database connection may be held while it runs.
type blockingProjectHash struct {
	*hasher.Argon2idHash
	entered, release chan struct{}
}

func (h *blockingProjectHash) Compare(password, encoded string) error {
	close(h.entered)
	<-h.release
	return h.Argon2idHash.Compare(password, encoded)
}

func projectPasswordHashDrill(t *testing.T, admin *pgx.Conn, key projectruntime.Key, registry *projectruntime.Registry, cfg appauth.ProjectPasswordConfig, deps appauth.ProjectPasswordDependencies, realHash *hasher.Argon2idHash, input passwordservice.LoginInput, suspend bool) {
	t.Helper()
	ctx := t.Context()
	hash := &blockingProjectHash{Argon2idHash: realHash, entered: make(chan struct{}), release: make(chan struct{})}
	deps.Hash = hasher.NewBounded(hash, 1)
	svc, err := appauth.NewProjectPassword(ctx, key, cfg, deps)
	require.NoError(t, err)
	type outcome struct {
		result *passwordservice.LoginResult
		err    error
	}
	result := make(chan outcome, 1)
	finished := make(chan struct{})
	released := false
	unblock := func() {
		if !released {
			close(hash.release)
			released = true
		}
	}
	go func() { defer close(finished); value, err := svc.Login(ctx, input); result <- outcome{value, err} }()
	t.Cleanup(func() {
		unblock()
		select {
		case <-finished:
		case <-time.After(6 * time.Second):
			t.Error("login fixture failed to drain")
		}
	})
	select {
	case <-hash.entered:
	case <-time.After(4 * time.Second):
		unblock()
		t.Fatal("login did not reach hash")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	probeErr := registry.Use(probeCtx, key, func(ctx context.Context, database projectruntime.Database) error {
		tx, err := database.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		var value int
		if err := tx.QueryRow(ctx, `SELECT 1`).Scan(&value); err != nil {
			return err
		}
		return tx.Commit(ctx)
	})
	cancel()
	if suspend {
		_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, key.Binding.ProjectID)
		t.Cleanup(func() {
			_, err := admin.Exec(context.WithoutCancel(ctx), `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, key.Binding.ProjectID, key.Version)
			require.NoError(t, err)
		})
	}
	unblock()
	received := <-result
	require.NoError(t, probeErr, "one-connection pool must remain usable during Argon2 work")
	require.NoError(t, err)
	if suspend {
		require.ErrorIs(t, received.err, projectdomain.ErrConflict)
		require.Nil(t, received.result)
	} else {
		require.NoError(t, received.err)
		require.NotEmpty(t, received.result.Token)
	}
}

func projectPasswordFixtureConfig() appauth.ProjectPasswordConfig {
	return appauth.ProjectPasswordConfig{Timeout: 5 * time.Second, Capacity: passwordservice.CapacityConfig{HashConcurrency: 1, LoginIPLimit: 100, LoginEmailLimit: 100, LoginGlobalLimit: 100}, Session: sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute}}
}
