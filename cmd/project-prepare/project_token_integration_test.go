package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

var (
	tokenFixtureUsers  = []string{"f8600000-0000-4000-8000-000000000001", "f8600000-0000-4000-8000-000000000002", "f8600000-0000-4000-8000-000000000003"}
	tokenFixtureEmails = []string{"project-token@example.test", "project-token-mfa@example.test", "project-token-otp@example.test"}
)

const (
	tokenConsumerID                                   = "reports-api"
	tokenConsumerSecret                               = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokenFixtureIP                                    = "192.0.2.86"
	tokenFixturePermission accessdomain.PermissionKey = "reports.read"
)

type projectTokenFixture struct {
	db                   *pgx.Conn
	rdb                  *redis.Client
	key                  projectruntime.Key
	deps                 appauth.ProjectSMTPDependencies
	hash                 *hasher.Bounded
	listener             net.Listener
	sourceUser, password string
}

func (f projectTokenFixture) run(t *testing.T, ctx context.Context) {
	t.Helper()
	_, err := f.db.Exec(ctx, `CREATE TEMP TABLE token_policy_before AS TABLE auth.auth_settings;
 UPDATE auth.auth_settings SET password_enabled=true,email_otp_enabled=true,password_email_verification='optional',token_session_exchange_enabled=true,token_native_enabled=true;
 INSERT INTO auth.roles(key,name) VALUES('project_token_fixture','Token fixture');
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,$1 FROM auth.roles WHERE key='project_token_fixture'`, string(tokenFixturePermission))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.token_issuance_audit WHERE user_id=ANY($1::uuid[]); DELETE FROM auth.refresh_audit WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.password_audit WHERE user_id=ANY($1::uuid[]); DELETE FROM auth.email_login_audit WHERE user_id=ANY($1::uuid[]); DELETE FROM auth.mfa_audit WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.refresh_tokens WHERE session_id IN(SELECT id FROM auth.sessions WHERE user_id=ANY($1::uuid[]));
 DELETE FROM auth.users WHERE id=ANY($1::uuid[]); DELETE FROM auth.roles WHERE key='project_token_fixture';
 DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM token_policy_before`, tokenFixtureUsers)
		require.NoError(t, err)
	})
	for i, user := range tokenFixtureUsers {
		_, err = f.db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1); INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,$2,clock_timestamp());
 INSERT INTO auth.password_credentials(user_id,email_id,password_hash) SELECT $1,e.id,p.password_hash FROM auth.user_emails e CROSS JOIN auth.password_credentials p WHERE e.user_id=$1 AND p.user_id=$3;
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='project_token_fixture'`, user, tokenFixtureEmails[i], f.sourceUser)
		require.NoError(t, err)
	}
	config, err := f.deps.Reader.LoadAuthConfiguration(ctx, f.key, f.deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(f.key.Binding.ProjectID))
	require.NoError(t, err)
	ciphers := map[string]*secretbox.Cipher{}
	for _, purpose := range []string{"jwt-issuance-limits:v1", "password-reset:v1", "email-login:v1", "mfa:v1"} {
		scoped, err := scope.Purpose(purpose)
		require.NoError(t, err)
		ciphers[purpose], err = secretbox.NewScoped(config.EncryptionKey(), scoped)
		require.NoError(t, err)
	}
	keys := []string{}
	f.cleanupTokenLimits(t, ctx, scope, ciphers, &keys)
	client, err := appauth.NewProjectTokenRedis(f.rdb)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	base := projectPasswordFixtureConfig()
	catalog, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: tokenFixturePermission, Name: "Read reports"}})
	require.NoError(t, err)
	consumerHash := sha256.Sum256([]byte(tokenConsumerSecret))
	cfg := appauth.ProjectTokenConfig{
		Introspection: &appauth.ProjectIntrospectionConfig{Clients: []tokenservice.IntrospectionClientConfig{{ID: tokenConsumerID, SecretHashes: []string{hex.EncodeToString(consumerHash[:])}, Audiences: []string{"reports"}}}, ConsumerPerMinute: 100, ProjectPerMinute: 100},
		Enabled:       true, Issuer: "https://project-token.example.test", Catalog: catalog, Limits: tokenredis.DefaultLimits(), Timeout: 15 * time.Second,
		Tokens: tokenservice.Config{AccessTTL: 2 * time.Minute, Resources: []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{tokenFixturePermission}}, {Audience: "reports-export", Permissions: []accessdomain.PermissionKey{tokenFixturePermission}}}, Native: &tokenservice.NativePolicy{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour, Sessions: base.Session}},
		Native: appauth.ProjectNativeConfig{PasswordEnabled: true, Capacity: base.Capacity, EmailOTP: otpservice.Config{Enabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000}, MFA: mfaservice.Config{Enabled: true, Issuer: "Project tokens", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}, SMTPAllowedTargets: []string{f.listener.Addr().String()}},
	}
	service, err := appauth.NewProjectTokens(ctx, f.key, cfg, appauth.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, IssuanceRedis: client, Hash: f.hash})
	require.NoError(t, err)
	jwks, err := service.PublicJWKS(ctx)
	require.NoError(t, err)
	public, err := authjwt.ParsePublicKeys(jwks)
	require.NoError(t, err)
	verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: cfg.Issuer, Audience: "reports", Mode: authjwt.Strict}, public, time.Now())
	require.NoError(t, err)
	hash := tokengenerate.New().Hash(tokenFixtureUsers[0])
	var sessionID string
	require.NoError(t, f.db.QueryRow(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address,primary_method,primary_verified_at)
 VALUES($1,$2,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','fixture',$3,'password',clock_timestamp()) RETURNING id`, hash, tokenFixtureUsers[0], tokenFixtureIP).Scan(&sessionID))
	input := tokenservice.ExchangeInput{Actor: accessservice.Principal{UserID: accountdomain.UserID(tokenFixtureUsers[0]), TokenHash: hash}, SessionID: sessionID, Audience: "reports", Scope: []accessdomain.PermissionKey{tokenFixturePermission}, IP: tokenFixtureIP}
	exchanged, err := service.Exchange(ctx, input)
	require.NoError(t, err)
	claims, err := verifier.VerifySignature(ctx, exchanged.Raw, time.Now())
	require.NoError(t, err)
	require.Equal(t, tokenFixtureUsers[0], claims.Subject)
	foreign, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://foreign.example.test", Audience: "reports", Mode: authjwt.Strict}, public, time.Now())
	require.NoError(t, err)
	_, err = foreign.VerifySignature(ctx, exchanged.Raw, time.Now())
	require.Error(t, err)
	f.introspectionIsolation(t, ctx, service, cfg, client, input, exchanged.Raw)
	f.nativeTokenFlows(t, ctx, service, cfg, verifier, ciphers, scope, &keys)
	_, err = f.db.Exec(ctx, `UPDATE auth.users SET status='blocked',auth_version=auth_version+1 WHERE id=$1`, tokenFixtureUsers[0])
	require.NoError(t, err)
	rejected, err := service.Exchange(ctx, input)
	require.Error(t, err)
	require.Nil(t, rejected)
	consumer, ok := service.Authenticate(tokenConsumerID, tokenConsumerSecret)
	require.True(t, ok)
	inactive, err := service.Inspect(ctx, consumer, exchanged.Raw)
	require.NoError(t, err)
	require.Equal(t, tokenservice.IntrospectionResult{}, inactive, "blocked owner must return only inactive")
}
