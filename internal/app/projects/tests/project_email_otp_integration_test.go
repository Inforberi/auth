package projects_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

const otpFixtureIP = "192.0.2.84"

var (
	otpFixtureUsers  = []string{"f8400000-0000-4000-8000-000000000001", "f8400000-0000-4000-8000-000000000002", "f8400000-0000-4000-8000-000000000003", "f8400000-0000-4000-8000-000000000004"}
	otpFixtureEmails = []string{"project-otp@example.test", "project-reauth@example.test", "project-otp-mfa@example.test", "project-otp-closed@example.test"}
)

type projectOTPFixture struct {
	db     *pgx.Conn
	rdb    *redis.Client
	key    projectruntime.Key
	deps   appauth.ProjectSMTPDependencies
	scope  realmscope.Scope
	cipher *secretbox.Cipher
	root   string
	cfg    appauth.ProjectEmailOTPConfig
}

func projectEmailOTPDrill(t *testing.T, ctx context.Context, db *pgx.Conn, rdb *redis.Client, key projectruntime.Key, deps appauth.ProjectSMTPDependencies, sourceUser string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		err := listener.Close()
		if !errors.Is(err, net.ErrClosed) {
			require.NoError(t, err)
		}
	})
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(rawPort)
	require.NoError(t, err)
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("email-login:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	f := projectOTPFixture{db: db, rdb: rdb, key: key, deps: deps, scope: scope, cipher: cipher, root: configuration.EncryptionKey(), cfg: appauth.ProjectEmailOTPConfig{
		OTP:     otpservice.Config{Enabled: true, ReauthenticationEnabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000},
		Session: projectPasswordFixtureConfig().Session, Timeout: 10 * time.Second,
	}}
	_, err = db.Exec(ctx, `CREATE TEMP TABLE otp_policy_before AS TABLE auth.auth_settings; CREATE TEMP TABLE otp_smtp_before AS TABLE auth.smtp_settings;
 UPDATE auth.smtp_settings SET configuration=jsonb_set(configuration,'{port}',to_jsonb($1::int));
 UPDATE auth.auth_settings SET password_enabled=true,email_otp_enabled=true`, port)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.mfa_audit WHERE user_id=ANY($1::uuid[]); DELETE FROM auth.email_login_audit WHERE user_id=ANY($1::uuid[]); DELETE FROM auth.users WHERE id=ANY($1::uuid[]);
 DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM otp_policy_before; DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings SELECT * FROM otp_smtp_before`, otpFixtureUsers)
		require.NoError(t, err)
	})
	f.trackLimits(t, ctx)
	for i, user := range otpFixtureUsers {
		_, err = db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1); INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,$2,clock_timestamp())`, user, otpFixtureEmails[i])
		require.NoError(t, err)
		if i != 1 {
			_, err = db.Exec(ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) SELECT $1,e.id,p.password_hash FROM auth.user_emails e CROSS JOIN auth.password_credentials p WHERE e.user_id=$1 AND p.user_id=$2`, user, sourceUser)
			require.NoError(t, err)
		}
	}
	svc, err := appauth.NewProjectEmailOTP(ctx, key, f.cfg, []string{listener.Addr().String()}, deps)
	require.NoError(t, err)
	request, err := svc.Request(ctx, otpFixtureEmails[0], otpFixtureIP)
	require.NoError(t, err)
	code := f.code(t, ctx, request.Binding, "")
	f.delivery(t, ctx, listener, request.Binding)
	input := otpservice.ConfirmInput{Code: code, Binding: request.Binding, UserAgent: "project OTP fixture", IP: otpFixtureIP}
	wrong := input
	wrong.Code = string('0'+(input.Code[0]-'0'+1)%10) + input.Code[1:]
	result, err := svc.Confirm(ctx, wrong)
	require.Error(t, err)
	require.Nil(t, result)
	result, err = svc.Confirm(ctx, input)
	require.NoError(t, err)
	require.NotEmpty(t, result.RawToken)
	require.Nil(t, result.Challenge)
	var method string
	var passwordProof bool
	require.NoError(t, db.QueryRow(ctx, `SELECT primary_method,password_verified_at IS NOT NULL FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(result.RawToken)).Scan(&method, &passwordProof))
	require.Equal(t, "emailotp", method)
	require.False(t, passwordProof)
	result, err = svc.Confirm(ctx, input)
	require.Error(t, err)
	require.Nil(t, result)
	f.reauthentication(t, ctx, svc)
	f.mfa(t, ctx, listener)
	// A caller hook must never replace the current stored project policy.
	f.cfg.OTP.CheckPolicy = func(context.Context) error { return nil }
	svc, err = appauth.NewProjectEmailOTP(ctx, key, f.cfg, []string{listener.Addr().String()}, deps)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `UPDATE auth.auth_settings SET email_otp_enabled=false`)
	require.NoError(t, err)
	rejected, err := svc.Request(ctx, "policy-reject@example.test", otpFixtureIP)
	require.Error(t, err)
	require.Nil(t, rejected)
}

func (f projectOTPFixture) code(t *testing.T, ctx context.Context, binding, purpose string) string {
	t.Helper()
	var encrypted []byte
	require.NoError(t, f.db.QueryRow(ctx, `SELECT payload FROM auth.email_login_outbox WHERE digest=$1`, f.cipher.Digest(purpose+"binding:"+binding)).Scan(&encrypted))
	plain, err := f.cipher.Open(encrypted)
	require.NoError(t, err)
	defer clear(plain)
	var mail struct{ Body string }
	require.NoError(t, json.Unmarshal(plain, &mail))
	match := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(mail.Body)
	require.Len(t, match, 2)
	return match[1]
}

func (f projectOTPFixture) reauthentication(t *testing.T, ctx context.Context, svc *appauth.ProjectEmailOTP) {
	t.Helper()
	user := otpFixtureUsers[1]
	hash := tokengenerate.New().Hash(user)
	_, err := f.db.Exec(ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) VALUES('https://accounts.google.com','project-otp-reauth',$1);
 INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address,primary_method,primary_verified_at)
 VALUES($2,$1,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','fixture',$3,'oidc',clock_timestamp())`, user, hash, otpFixtureIP)
	require.NoError(t, err)
	proof := mfaservice.Proof{UserID: accountdomain.UserID(user), TokenHash: hash, AuthVersion: 1}
	requested, err := svc.RequestReauthentication(ctx, proof, otpFixtureEmails[1], otpFixtureIP)
	require.NoError(t, err)
	input := otpservice.ReauthenticationInput{Proof: proof, Binding: requested.Binding, Code: f.code(t, ctx, requested.Binding, "reauth:"), IP: otpFixtureIP}
	result, err := svc.ConfirmReauthentication(ctx, input)
	require.NoError(t, err)
	require.NotEmpty(t, result.Token)
	var rotated bool
	var count int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*),bool_and(token_hash=$2 AND primary_method='oidc' AND email_reauthenticated_at IS NOT NULL) FROM auth.sessions WHERE user_id=$1`, user, tokengenerate.New().Hash(result.Token)).Scan(&count, &rotated))
	require.Equal(t, 1, count)
	require.True(t, rotated)
	result, err = svc.ConfirmReauthentication(ctx, input)
	require.Error(t, err)
	require.Nil(t, result)
}

func (f projectOTPFixture) trackLimits(t *testing.T, ctx context.Context) {
	t.Helper()
	prefix, err := f.scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
	require.NoError(t, err)
	logical := []string{"request:ip:" + otpFixtureIP, "request:project", "confirm:ip:" + otpFixtureIP, "confirm:project", "reauth:request:user:" + otpFixtureUsers[1], "reauth:confirm:user:" + otpFixtureUsers[1]}
	for _, email := range append(append([]string{}, otpFixtureEmails...), "policy-reject@example.test") {
		logical = append(logical, "request:email:"+email, "request:cooldown:"+email)
	}
	keys := make([]string, 0, len(logical))
	for _, name := range logical {
		keys = append(keys, prefix+f.cipher.Digest(name))
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, f.rdb.Del(cleanup, keys...).Err())
	})
}
