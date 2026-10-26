package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func projectEmailDrill(t *testing.T, admin, db *pgx.Conn, rdb *redis.Client, key projectruntime.Key, deps appauth.ProjectSMTPDependencies, listener net.Listener) {
	t.Helper()
	ctx := t.Context()
	const user = "f8200000-0000-4000-8000-000000000001"
	const contact = "f8200000-0000-4000-8000-000000000002"
	const email = "runtime-email@example.test"
	const ip = "192.0.2.82"
	_, err := db.Exec(ctx, `CREATE TEMP TABLE email_policy_before AS TABLE auth.auth_settings;
 UPDATE auth.auth_settings SET password_enabled=true,password_email_verification='optional';
 INSERT INTO auth.users(id) VALUES($1);
 INSERT INTO auth.user_emails(id,user_id,email) VALUES($2,$1,$3)`, user, contact, email)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.users WHERE id=$1; DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM email_policy_before`, user)
		require.NoError(t, err)
	})
	hash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1)
	encoded, err := hash.GenerateHash(ctx, []byte("Synthetic-original-password-82!"))
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES($1,$2,$3)`, user, contact, encoded)
	require.NoError(t, err)
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	ciphers := make([]*secretbox.Cipher, 2)
	for i, purpose := range []string{"email-verification:v1", "password-reset:v1"} {
		scoped, err := scope.Purpose(purpose)
		require.NoError(t, err)
		ciphers[i], err = secretbox.NewScoped(configuration.EncryptionKey(), scoped)
		require.NoError(t, err)
	}
	var redisKeys []string
	for i, group := range []struct {
		purpose, legacy string
		keys            []string
	}{
		{"email-verification-limit", "auth:email-verification:limit:", []string{"resend-ip:" + ip, "resend-email:" + email, "confirm-ip:" + ip}},
		{"password-limit", "auth:password-recovery:limit:", []string{"forgot-ip:" + ip, "forgot-email:" + email, "reset-ip:" + ip, "reset-global"}},
	} {
		prefix, err := scope.RedisPrefix(group.purpose, group.legacy)
		require.NoError(t, err)
		for _, logical := range group.keys {
			redisKeys = append(redisKeys, prefix+ciphers[i].Digest(logical))
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, rdb.Del(cleanup, redisKeys...).Err())
		count, err := rdb.DBSize(cleanup).Result()
		require.NoError(t, err)
		require.Zero(t, count)
	})
	cfg := appauth.ProjectEmailConfig{VerificationEnabled: true, RecoveryEnabled: true, Origin: "https://runtime-email.example.test", Verification: accountservice.Config{
		URL: "https://runtime-email.example.test/verify-email", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100,
	}, Password: passwordservice.Config{ResetURL: "https://runtime-email.example.test/reset-password", ResetTokenTTL: time.Hour, ResetGlobalLimit: 100}}
	service, err := appauth.NewProjectEmail(ctx, key, cfg, []string{listener.Addr().String()}, appauth.ProjectEmailDependencies{ProjectSMTPDependencies: deps, Hash: hash})
	require.NoError(t, err)
	require.NoError(t, service.ResendVerification(ctx, email, ip))
	require.NoError(t, service.ForgotPassword(ctx, email, ip))
	var verificationPayload, resetPayload []byte
	require.NoError(t, db.QueryRow(ctx, `SELECT payload FROM auth.email_verification_outbox o JOIN auth.email_verifications v USING(digest) WHERE v.email_id=$1`, contact).Scan(&verificationPayload))
	require.NoError(t, db.QueryRow(ctx, `SELECT payload FROM auth.password_reset_outbox o JOIN auth.password_resets r USING(digest) WHERE r.user_id=$1`, user).Scan(&resetPayload))
	plain, err := ciphers[0].Open(verificationPayload)
	require.NoError(t, err)
	var verification struct{ To, Link string }
	require.NoError(t, json.Unmarshal(plain, &verification))
	clear(plain)
	require.Equal(t, email, verification.To)
	link, err := url.Parse(verification.Link)
	require.NoError(t, err)
	verificationToken := link.Query().Get("token")
	require.Len(t, verificationToken, 43)
	plain, err = ciphers[1].Open(resetPayload)
	require.NoError(t, err)
	var reset struct{ To, Body string }
	require.NoError(t, json.Unmarshal(plain, &reset))
	clear(plain)
	require.Equal(t, email, reset.To)
	match := regexp.MustCompile(`token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(reset.Body)
	require.Len(t, match, 2)
	require.Contains(t, reset.Body, cfg.Password.ResetURL)
	_, err = ciphers[1].Open(verificationPayload)
	require.Error(t, err, "queue purposes must remain distinct")
	projectEmailPageDrill(t, deps.Reader, key)
	runner, err := appauth.NewProjectDelivery(appauth.ProjectDeliveryConfig{Parallelism: 1, PageSize: projectruntime.StateBatchSize, Interval: time.Second, SMTPAllowedTargets: []string{listener.Addr().String()}}, deps)
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	released := make(chan struct{})
	close(released)
	for range 2 {
		done := make(chan error, 1)
		go projectSMTPGreeting(runCtx, listener, make(chan struct{}), released, done)
		t.Cleanup(func() {
			select {
			case smtpErr := <-done:
				require.NoError(t, smtpErr)
			case <-time.After(6 * time.Second):
				t.Error("SMTP fixture did not drain")
			}
		})
	}
	reported := make(chan error, projectruntime.StateBatchSize)
	finished := make(chan struct{})
	var runErr error
	go func() {
		defer close(finished)
		runErr = runner.Run(runCtx, func(err error) {
			select {
			case reported <- err:
			case <-runCtx.Done():
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("delivery scheduler did not drain")
		}
	})
	timeout := time.NewTimer(12 * time.Second)
	defer timeout.Stop()
	waiting := true
	for waiting {
		select {
		case <-reported:
			var retried bool
			require.NoError(t, db.QueryRow(ctx, `SELECT
    EXISTS(SELECT 1 FROM auth.email_verification_outbox o JOIN auth.email_verifications v USING(digest) WHERE v.email_id=$1 AND o.attempts=1 AND o.lease IS NULL AND o.available_at>clock_timestamp())
    AND EXISTS(SELECT 1 FROM auth.password_reset_outbox o JOIN auth.password_resets r USING(digest) WHERE r.user_id=$2 AND o.attempts=1 AND o.lease IS NULL AND o.available_at>clock_timestamp())`, contact, user).Scan(&retried))
			if retried {
				waiting = false
			}
		case <-timeout.C:
			t.Fatal("project delivery did not retry both queues")
		}
	}
	cancel()
	<-finished
	require.True(t, errors.Is(runErr, context.Canceled))
	require.NoError(t, service.ConfirmVerification(ctx, verificationToken, ip))
	require.Error(t, service.ConfirmVerification(ctx, verificationToken, ip))
	const replacement = "Synthetic-replacement-password-82!"
	require.NoError(t, service.ResetPassword(ctx, match[1], replacement, replacement, ip))
	require.Error(t, service.ResetPassword(ctx, match[1], replacement, replacement, ip))
	var verified bool
	var actualHash string
	require.NoError(t, db.QueryRow(ctx, `SELECT e.verified_at IS NOT NULL,p.password_hash FROM auth.user_emails e JOIN auth.password_credentials p ON p.email_id=e.id WHERE e.id=$1`, contact).Scan(&verified, &actualHash))
	require.True(t, verified)
	require.NoError(t, hash.Compare(ctx, replacement, actualHash))
	t.Run("remaining project account scenarios", func(t *testing.T) {
		(projectAccountFixture{admin: admin, sourceUser: user, password: replacement, db: db, rdb: rdb, key: key, deps: deps, hash: hash, cfg: cfg, ciphers: ciphers}).run(t, ctx)
	})
	t.Run("project email OTP scenarios", func(t *testing.T) {
		projectEmailOTPDrill(t, ctx, db, rdb, key, deps, user)
	})
	t.Run("project external login isolation", func(t *testing.T) {
		projectOIDCDrill(t, ctx, admin, db, rdb, key, deps, user, hash)
	})
	t.Run("project JWT exchange and native", func(t *testing.T) {
		(projectTokenFixture{db: db, rdb: rdb, key: key, deps: deps, hash: hash, listener: listener, sourceUser: user, password: replacement}).run(t, ctx)
	})
	t.Run("selected feature readiness", func(t *testing.T) {
		(projectProfileFixture{admin: admin, db: db, rdb: rdb, key: key, deps: deps, hash: hash, listener: listener, sourceUser: user, password: replacement}).run(t, ctx)
	})
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, key.Binding.ProjectID, key.Version)
		require.NoError(t, err)
	})
	require.Error(t, service.ForgotPassword(ctx, email, ip))
	var pending int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.password_resets WHERE user_id=$1`, user).Scan(&pending))
	require.Zero(t, pending, "suspended project must not issue another reset")
	var after catalog.RuntimeCursor
	for range 100 {
		keys, next, err := deps.Reader.PageRuntimes(ctx, after, 1)
		require.NoError(t, err)
		for _, item := range keys {
			require.NotEqual(t, key.Binding.ProjectID, item.Binding.ProjectID)
		}
		if next.CreatedAt.IsZero() {
			break
		}
		after = next
	}
}

func projectEmailPageDrill(t *testing.T, reader *catalog.RuntimeCredentialReader, key projectruntime.Key) {
	t.Helper()
	var cursor catalog.RuntimeCursor
	found := false
	seen := make(map[string]bool)
	for range 100 {
		keys, next, err := reader.PageRuntimes(t.Context(), cursor, 1)
		require.NoError(t, err)
		for _, item := range keys {
			id := string(item.Binding.ProjectID)
			require.False(t, seen[id])
			seen[id] = true
			if item == key {
				found = true
			}
		}
		if next.CreatedAt.IsZero() {
			break
		}
		cursor = next
	}
	require.True(t, found, "background selection must find ready project without user traffic")
	_, _, err := reader.PageRuntimes(t.Context(), catalog.RuntimeCursor{}, projectruntime.StateBatchSize+1)
	require.Error(t, err)
}
