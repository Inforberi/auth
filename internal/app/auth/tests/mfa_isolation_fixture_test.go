package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaredis "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/redis"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

const isolationUser accountdomain.UserID = "c8100000-0000-4000-8000-000000000001"

type mfaIsolationRealm struct {
	db       *pgxpool.Pool
	actor    accessservice.Principal
	scope    realmscope.Scope
	login    *sessionservice.Login
	mfa      *mfalogin.Login
	cipher   *secretbox.Cipher
	tokens   *tokenservice.Service
	keys     *authjwt.PublicKeys
	verifier *authjwt.Verifier
	issuer   string
}

func isolationAdmin(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("AUTH_MFA_ISOLATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires explicit disposable MFA isolation PostgreSQL fixture")
	}
	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	require.Equal(t, "auth_storage_test", cfg.Database)
	require.Equal(t, "auth", cfg.User)
	require.Equal(t, "127.0.0.1", cfg.Host)
	admin, err := pgx.ConnectConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close(context.WithoutCancel(t.Context()))) })
	return admin
}

func isolationDatabase(t *testing.T, admin *pgx.Conn, name string) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()
	var occupied bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, name).Scan(&occupied))
	require.False(t, occupied, "fixture must not replace existing objects")
	identifier := pgx.Identifier{name}.Sanitize()
	_, err := admin.Exec(ctx, `CREATE ROLE `+identifier+` LOGIN NOINHERIT PASSWORD 'Isolation-fixture-only-72!'`)
	require.NoError(t, err)
	var db *pgxpool.Pool
	created := false
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if db != nil {
			db.Close()
		}
		if created {
			_, err := admin.Exec(cleanup, `DROP DATABASE `+identifier)
			require.NoError(t, err)
		}
		_, err := admin.Exec(cleanup, `DROP ROLE `+identifier)
		require.NoError(t, err)
	})
	_, err = admin.Exec(ctx, `CREATE DATABASE `+identifier+` OWNER `+identifier)
	require.NoError(t, err)
	created = true
	_, err = admin.Exec(ctx, `REVOKE ALL ON DATABASE `+identifier+` FROM PUBLIC`)
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(admin.Config().ConnString())
	require.NoError(t, err)
	cfg.ConnConfig.Database, cfg.ConnConfig.User, cfg.ConnConfig.Password = name, name, "Isolation-fixture-only-72!"
	cfg.MaxConns, cfg.MinConns = 4, 0
	db, err = pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, db.Ping(ctx))
	migrateFixture(t, db, ctx, "up")
	return db
}

func newMFAIsolationRealm(t *testing.T, db *pgxpool.Pool, kind, id, issuer string) mfaIsolationRealm {
	t.Helper()
	ctx := t.Context()
	r := mfaIsolationRealm{db: db, issuer: issuer, actor: mfaTokenPolicyActor(t, db, ctx)}
	updateMFATokenRequirement(t, db, ctx, r.actor, "", "realm", false)
	accessExec(t, db, ctx, `INSERT INTO auth.users(id) VALUES($1)`, isolationUser)
	accessExec(t, db, ctx, `INSERT INTO auth.user_emails(id,user_id,email,verified_at)
 VALUES('c8100000-0000-4000-8000-000000000002',$1,'same-user@example.test',clock_timestamp())`, isolationUser)
	accessExec(t, db, ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash)
 VALUES($1,'c8100000-0000-4000-8000-000000000002','old-hash')`, isolationUser)
	accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('isolation_reader','Reader') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,unnest(ARRAY['orders.read','orders.write']) FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, isolationUser)
	var err error
	r.scope, err = realmscope.New(kind, id)
	require.NoError(t, err)
	purpose, err := r.scope.Purpose("mfa:v1")
	require.NoError(t, err)
	// Deliberately reuse the root key and user UUID: isolation must include the realm purpose.
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), purpose)
	require.NoError(t, err)
	r.cipher = cipher
	r.mfa, err = mfalogin.NewLogin(mfapostgres.New(db), cipher, totp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{
		ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
		UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100,
	})
	require.NoError(t, err)
	r.login = sessionservice.NewLogin(sessionservice.New(clock.UTCClock{}, sessionpostgres.New(db), tokengenerate.New(), nativePolicyFixture().Sessions), r.mfa)
	signer, keys := jwtSigningIssuerFixture(t, issuer)
	r.keys, r.tokens = keys, nativeTokenService(t, db, signer)
	r.verifier, err = authjwt.NewVerifier(authjwt.Expectations{Issuer: issuer, Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
	require.NoError(t, err)
	return r
}

func (r mfaIsolationRealm) primary(t *testing.T, ctx context.Context) mfaservice.PrimaryProof {
	t.Helper()
	proof := mfaservice.PrimaryProof{UserID: isolationUser, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()}
	require.NoError(t, r.db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, isolationUser).Scan(&proof.AuthVersion))
	return proof
}

func (r mfaIsolationRealm) snapshot(t *testing.T, ctx context.Context) string {
	t.Helper()
	var snapshot string
	require.NoError(t, r.db.QueryRow(ctx, `SELECT jsonb_build_object(
 'policy',(SELECT to_jsonb(p) FROM auth.mfa_settings p),
 'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY u.id) FROM auth.users u),
 'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM auth.roles r),
 'permissions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.role_id,p.permission_key) FROM auth.role_permissions p),
 'assignments',(SELECT jsonb_agg(to_jsonb(ur) ORDER BY ur.user_id,ur.role_id) FROM auth.user_roles ur),
 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM auth.sessions s),
 'factors',(SELECT jsonb_agg(to_jsonb(f) ORDER BY f.user_id) FROM auth.mfa_totp f),
 'recovery',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.user_id,r.digest) FROM auth.mfa_recovery_codes r),
 'pending',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.digest) FROM auth.mfa_login_challenges c),
 'enrollment',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.user_id) FROM auth.mfa_enrollments e),
 'families',(SELECT jsonb_agg(to_jsonb(f) ORDER BY f.session_id) FROM auth.refresh_families f),
 'refresh',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.token_hash) FROM auth.refresh_tokens r),
 'policy_audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM auth.mfa_settings_audit a),
 'factor_audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM auth.mfa_audit a),
 'access_audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM auth.access_audit a)
 )::text`).Scan(&snapshot))
	digest := sha256.Sum256([]byte(snapshot))
	return hex.EncodeToString(digest[:])
}

func (r mfaIsolationRealm) exchange(t *testing.T, cookie string) (tokenservice.ExchangeInput, authjwt.Claims, string) {
	t.Helper()
	input := tokenservice.ExchangeInput{Actor: accessservice.Principal{UserID: isolationUser, TokenHash: tokengenerate.New().Hash(cookie)}, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}, IP: "192.0.2.1"}
	require.NoError(t, r.db.QueryRow(t.Context(), `SELECT id FROM auth.sessions WHERE token_hash=$1`, input.Actor.TokenHash).Scan(&input.SessionID))
	result, err := r.tokens.Exchange(t.Context(), input)
	require.NoError(t, err)
	claims, err := r.verifier.VerifySignature(t.Context(), result.Raw, time.Now())
	require.NoError(t, err)
	return input, claims, result.Raw
}

func checkIsolationMFALimits(t *testing.T, realms []mfaIsolationRealm) {
	t.Helper()
	ctx := t.Context()
	addr := os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR")
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_PASSWORD"), DB: 15})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	count, err := rdb.DBSize(ctx).Result()
	require.NoError(t, err)
	require.Zero(t, count, "requires exclusive empty RedisDB15")
	var keys []string
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if len(keys) != 0 {
			require.NoError(t, rdb.Del(cleanup, keys...).Err())
		}
		count, err := rdb.DBSize(cleanup).Result()
		require.NoError(t, err)
		require.Zero(t, count)
	})
	for _, r := range realms {
		prefix, err := r.scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
		require.NoError(t, err)
		keys = append(keys, prefix+"project", prefix+"user:"+string(isolationUser))
		limits, err := mfaredis.NewScoped(rdb, r.scope)
		require.NoError(t, err)
		budgets := []mfaservice.Budget{{Key: "project", Count: 1}, {Key: "user:" + string(isolationUser), Count: 1}}
		allowed, err := limits.AllowAll(ctx, budgets)
		require.NoError(t, err)
		require.True(t, allowed, "another realm's exhausted project budget must not block this realm")
		allowed, err = limits.AllowAll(ctx, budgets)
		require.NoError(t, err)
		require.False(t, allowed)
	}
}
