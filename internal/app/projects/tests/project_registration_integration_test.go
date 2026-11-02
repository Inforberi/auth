package projects_test

import (
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func projectRegistrationDrill(t *testing.T, admin, db *pgx.Conn, rdb *redis.Client, key projectruntime.Key, base appauth.ProjectPasswordConfig, deps appauth.ProjectPasswordDependencies) {
	t.Helper()
	ctx := t.Context()
	const ip = "192.0.2.91"
	const password = "Synthetic-registration-password-91!"
	names := []string{"disabled", "optional", "required", "unprepared", "rollback", "password-off", "registration-off", "duplicate", "policy-race", "suspend"}
	emails := make([]string, len(names))
	for i, name := range names {
		emails[i] = "runtime-registration-" + name + "@example.test"
	}
	_, err := db.Exec(ctx, `CREATE TEMP TABLE registration_policy_before AS TABLE auth.auth_settings;
 CREATE TEMP TABLE registration_smtp_before AS TABLE auth.smtp_settings; DELETE FROM auth.smtp_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.sessions WHERE user_id IN(SELECT user_id FROM auth.user_emails WHERE email=ANY($1::text[]));
   DELETE FROM auth.users WHERE id IN(SELECT user_id FROM auth.user_emails WHERE email=ANY($1::text[]));
   DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM registration_policy_before;
   DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings SELECT * FROM registration_smtp_before`, emails)
		require.NoError(t, err)
	})
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("email-verification:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("email-verification-limit", "auth:email-verification:limit:")
	require.NoError(t, err)
	redisKeys := []string{prefix + cipher.Digest("register-ip:"+ip), prefix + cipher.Digest("register-global"), prefix + cipher.Digest("confirm-ip:"+ip)}
	purpose, err = scope.Purpose("password-reset:v1")
	require.NoError(t, err)
	passwordCipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	prefix, err = scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
	require.NoError(t, err)
	redisKeys = append(redisKeys, prefix+passwordCipher.Digest("login-ip:"+ip), prefix+passwordCipher.Digest("login-email:"+emails[2]))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, rdb.Del(cleanup, redisKeys...).Err())
	})
	cfg := base
	cfg.RegistrationVerification = &appauth.ProjectRegistrationVerification{Origin: "https://registration.example.test", Config: accountservice.Config{
		URL: "https://registration.example.test/verify-email", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 100, RegistrationGlobalLimit: 1000,
	}}
	service, err := appauth.NewProjectPassword(ctx, key, cfg, deps)
	require.NoError(t, err)
	bare, err := appauth.NewProjectPassword(ctx, key, base, deps)
	require.NoError(t, err)
	setPolicy := func(mode string) {
		_, err := db.Exec(ctx, `UPDATE auth.auth_settings SET password_enabled=true,registration_enabled=true,password_email_verification=$1`, mode)
		require.NoError(t, err)
	}
	users := func() int {
		var n int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&n))
		return n
	}
	userCount := func(email string) int {
		var n int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.user_emails WHERE email=$1`, email).Scan(&n))
		return n
	}
	for i, mode := range names[:3] {
		t.Run(mode, func(t *testing.T) {
			setPolicy(mode)
			register := service
			if mode == "disabled" {
				register = bare
			}
			result, err := register.Register(ctx, emails[i], password, "registration fixture", ip)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, mode == "required", result.VerificationRequired)
			require.Equal(t, mode == "required", result.Token == "")
			var verified, complete bool
			var queued, sessions int
			require.NoError(t, db.QueryRow(ctx, `SELECT e.verified_at IS NOT NULL,
    EXISTS(SELECT 1 FROM auth.password_credentials p WHERE p.user_id=e.user_id AND p.email_id=e.id)
    AND EXISTS(SELECT 1 FROM auth.user_profile p WHERE p.user_id=e.user_id),
    (SELECT count(*) FROM auth.email_verifications v JOIN auth.email_verification_outbox o USING(digest) WHERE v.email_id=e.id),
    (SELECT count(*) FROM auth.sessions s WHERE s.user_id=e.user_id)
    FROM auth.user_emails e WHERE e.email=$1`, emails[i]).Scan(&verified, &complete, &queued, &sessions))
			require.False(t, verified)
			require.True(t, complete)
			expected := 1
			if mode == "disabled" {
				expected = 0
			}
			require.Equal(t, expected, queued)
			if mode == "required" {
				require.Zero(t, sessions)
				input := passwordservice.LoginInput{Email: emails[i], Password: password, IP: ip, UserAgent: "registration fixture"}
				denied, err := service.Login(ctx, input)
				require.ErrorIs(t, err, accountdomain.ErrEmailUnverified)
				require.Nil(t, denied)
				var payload []byte
				require.NoError(t, db.QueryRow(ctx, `SELECT o.payload FROM auth.email_verification_outbox o JOIN auth.email_verifications v USING(digest) JOIN auth.user_emails e ON e.id=v.email_id WHERE e.email=$1`, emails[i]).Scan(&payload))
				plain, err := cipher.Open(payload)
				require.NoError(t, err)
				var message struct{ To, Link string }
				require.NoError(t, json.Unmarshal(plain, &message))
				clear(plain)
				require.Equal(t, emails[i], message.To)
				require.Contains(t, message.Link, cfg.RegistrationVerification.Config.URL)
				link, err := url.Parse(message.Link)
				require.NoError(t, err)
				err = deps.Registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
					limiter, err := accountredis.NewScoped(rdb, scope)
					if err != nil {
						return err
					}
					verifier := accountservice.New(accountpostgres.New(pool), limiter, cipher, nil, cfg.RegistrationVerification.Config)
					return verifier.Confirm(ctx, link.Query().Get("token"), ip)
				})
				require.NoError(t, err)
				session, err := service.Login(ctx, input)
				require.NoError(t, err)
				require.NotEmpty(t, session.Token)
			} else {
				require.Equal(t, 1, sessions)
			}
		})
	}
	t.Run("missing verifier rolls back account", func(t *testing.T) {
		setPolicy("optional")
		before := users()
		result, err := bare.Register(ctx, emails[3], password, "registration fixture", ip)
		require.ErrorIs(t, err, projectdomain.ErrUnavailable)
		require.Nil(t, result)
		require.Zero(t, userCount(emails[3]))
		require.Equal(t, before, users())
	})
	t.Run("outbox failure rolls back account", func(t *testing.T) {
		setPolicy("optional")
		before := users()
		_, err := db.Exec(ctx, `ALTER TABLE auth.email_verification_outbox ADD CONSTRAINT registration_fixture_reject CHECK(false) NOT VALID`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `ALTER TABLE auth.email_verification_outbox DROP CONSTRAINT registration_fixture_reject`)
			require.NoError(t, err)
		})
		result, err := service.Register(ctx, emails[4], password, "registration fixture", ip)
		require.Error(t, err)
		require.Nil(t, result)
		require.Zero(t, userCount(emails[4]))
		require.Equal(t, before, users())
	})
	for i, query := range []string{"UPDATE auth.auth_settings SET password_enabled=false", "UPDATE auth.auth_settings SET registration_enabled=false"} {
		t.Run(names[5+i], func(t *testing.T) {
			setPolicy("disabled")
			_, err := db.Exec(ctx, query)
			require.NoError(t, err)
			result, err := service.Register(ctx, emails[5+i], password, "registration fixture", ip)
			require.Error(t, err)
			require.Nil(t, result)
			require.Zero(t, userCount(emails[5+i]))
		})
	}
	t.Run("concurrent duplicate has one account and session", func(t *testing.T) {
		setPolicy("disabled")
		// Admit both hashes so this case exercises the database uniqueness race, not capacity rejection.
		concurrentDeps := deps
		concurrentDeps.Hash = hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 2)
		concurrentService, err := appauth.NewProjectPassword(ctx, key, cfg, concurrentDeps)
		require.NoError(t, err)
		var before int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&before))
		type outcome struct {
			result *passwordservice.RegisterResult
			err    error
		}
		outcomes := make(chan outcome, 2)
		start := make(chan struct{})
		var workers sync.WaitGroup
		for range 2 {
			workers.Go(func() {
				<-start
				result, err := concurrentService.Register(ctx, emails[7], password, "registration fixture", ip)
				outcomes <- outcome{result, err}
			})
		}
		close(start)
		workers.Wait()
		close(outcomes)
		successes := 0
		for got := range outcomes {
			if got.err == nil {
				successes++
				require.NotEmpty(t, got.result.Token)
			} else {
				require.ErrorIs(t, got.err, passworddomain.ErrEmailAlreadyExists)
				require.Nil(t, got.result)
			}
		}
		require.Equal(t, 1, successes)
		require.Equal(t, 1, userCount(emails[7]))
		var after, sessions int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&after))
		require.Equal(t, before+1, after)
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions s JOIN auth.user_emails e ON e.user_id=s.user_id WHERE e.email=$1`, emails[7]).Scan(&sessions))
		require.Equal(t, 1, sessions)
	})
	t.Run("policy changes during hash", func(t *testing.T) {
		setPolicy("disabled")
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `UPDATE auth.auth_settings SET registration_enabled=true`)
			require.NoError(t, err)
		})
		result, err := registrationDuringHash(t, ctx, key, cfg, deps, emails[8], password, ip, func() {
			_, err := db.Exec(ctx, `UPDATE auth.auth_settings SET registration_enabled=false`)
			require.NoError(t, err)
		})
		require.ErrorIs(t, err, settingsdomain.ErrRegistrationDisabled)
		require.Nil(t, result)
		require.Zero(t, userCount(emails[8]))
	})
	t.Run("suspend during hash never discloses token", func(t *testing.T) {
		setPolicy("disabled")
		t.Cleanup(func() {
			_, err := admin.Exec(context.WithoutCancel(ctx), `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, key.Binding.ProjectID, key.Version)
			require.NoError(t, err)
		})
		result, err := registrationDuringHash(t, ctx, key, cfg, deps, emails[9], password, ip, func() {
			_, err := admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, key.Binding.ProjectID)
			require.NoError(t, err)
		})
		require.ErrorIs(t, err, projectdomain.ErrConflict)
		require.Nil(t, result)
	})
}

type blockingRegistrationHash struct {
	*hasher.Argon2idHash
	started chan struct{}
	release chan struct{}
}

func (h *blockingRegistrationHash) GenerateHash(password []byte) (string, error) {
	close(h.started)
	<-h.release
	return h.Argon2idHash.GenerateHash(password)
}

func registrationDuringHash(t *testing.T, ctx context.Context, key projectruntime.Key, cfg appauth.ProjectPasswordConfig, deps appauth.ProjectPasswordDependencies, email, password, ip string, change func()) (*passwordservice.RegisterResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hash := &blockingRegistrationHash{Argon2idHash: hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), started: make(chan struct{}), release: make(chan struct{})}
	deps.Hash = hasher.NewBounded(hash, 1)
	service, err := appauth.NewProjectPassword(ctx, key, cfg, deps)
	require.NoError(t, err)
	var once sync.Once
	release := func() { once.Do(func() { close(hash.release) }) }
	type outcome struct {
		result *passwordservice.RegisterResult
		err    error
	}
	received := make(chan outcome, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, err := service.Register(ctx, email, password, "registration hash fixture", ip)
		received <- outcome{result, err}
	}()
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("registration hash worker did not drain")
		}
	})
	select {
	case <-hash.started:
	case <-ctx.Done():
		t.Fatal("registration did not enter hashing")
	}
	probe, stop := context.WithTimeout(ctx, time.Second)
	err = deps.Registry.UsePool(probe, key, func(ctx context.Context, pool *pgxpool.Pool) error {
		var one int
		return pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
	})
	stop()
	require.NoError(t, err, "single SQL connection must stay free during registration hashing")
	change()
	release()
	select {
	case got := <-received:
		return got.result, got.err
	case <-ctx.Done():
		t.Fatal("registration did not finish")
		return nil, ctx.Err()
	}
}
