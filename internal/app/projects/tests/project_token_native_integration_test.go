package projects_test

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func (f projectTokenFixture) nativeTokenFlows(t *testing.T, ctx context.Context, service *appauth.ProjectTokens, cfg appauth.ProjectTokenConfig, verifier *authjwt.Verifier, ciphers map[string]*secretbox.Cipher, scope realmscope.Scope, keys *[]string) {
	t.Helper()
	input := tokenservice.NativePasswordInput{Email: tokenFixtureEmails[0], Password: f.password, Audience: "reports", Scope: []accessdomain.PermissionKey{tokenFixturePermission}, IP: tokenFixtureIP, UserAgent: "native fixture"}
	result, err := service.LoginPassword(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, result.Tokens)
	require.Nil(t, result.Challenge)
	claims, err := verifier.VerifySignature(ctx, result.Tokens.Raw, time.Now())
	require.NoError(t, err)
	var profile string
	require.NoError(t, f.db.QueryRow(ctx, `SELECT credential_profile FROM auth.sessions WHERE id=$1`, claims.SessionID).Scan(&profile))
	require.Equal(t, "api", profile)
	refreshed, err := service.Refresh(ctx, tokenservice.RefreshInput{Token: result.Tokens.RefreshToken, IP: tokenFixtureIP})
	require.NoError(t, err)
	require.NotEqual(t, result.Tokens.RefreshToken, refreshed.RefreshToken)
	replay, err := service.Refresh(ctx, tokenservice.RefreshInput{Token: result.Tokens.RefreshToken, IP: tokenFixtureIP})
	require.Error(t, err)
	require.Nil(t, replay)
	replay, err = service.Refresh(ctx, tokenservice.RefreshInput{Token: refreshed.RefreshToken, IP: tokenFixtureIP})
	require.Error(t, err)
	require.Nil(t, replay)
	f.nativeEmailToken(t, ctx, service, verifier, ciphers["email-login:v1"])
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	encrypted, err := ciphers["mfa:v1"].Seal([]byte(tokenFixtureUsers[1] + "\x00" + secret))
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, tokenFixtureUsers[1], encrypted)
	require.NoError(t, err)
	input.Email = tokenFixtureEmails[1]
	challenged, err := service.LoginPassword(ctx, input)
	require.NoError(t, err)
	require.Nil(t, challenged.Tokens)
	require.NotNil(t, challenged.Challenge)
	mfaPrefix, err := scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
	require.NoError(t, err)
	*keys = append(*keys, mfaPrefix+"login:complete:subject:"+ciphers["mfa:v1"].Digest(challenged.Challenge.Token+":"+challenged.Challenge.Binding))
	var now time.Time
	require.NoError(t, f.db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now))
	code, err := totp.GenerateCode(secret, now)
	require.NoError(t, err)
	complete := mfalogin.CompleteLoginInput{Token: challenged.Challenge.Token, Binding: challenged.Challenge.Binding, Code: code, IP: tokenFixtureIP, UserAgent: input.UserAgent}
	browserCfg := projectPasswordFixtureConfig()
	browserCfg.MFA = cfg.Native.MFA
	browser, err := appauth.NewProjectPassword(ctx, f.key, browserCfg, appauth.ProjectPasswordDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, Hash: f.hash})
	require.NoError(t, err)
	wrong, err := browser.CompleteMFA(ctx, complete)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	require.Nil(t, wrong)
	completed, err := service.CompleteNativeMFA(ctx, complete)
	require.NoError(t, err)
	verified, err := verifier.VerifySignature(ctx, completed.Raw, time.Now())
	require.NoError(t, err)
	require.Equal(t, tokenFixtureUsers[1], verified.Subject)
	completed, err = service.CompleteNativeMFA(ctx, complete)
	require.Error(t, err)
	require.Nil(t, completed)
}

func (f projectTokenFixture) nativeEmailToken(t *testing.T, ctx context.Context, service *appauth.ProjectTokens, verifier *authjwt.Verifier, cipher *secretbox.Cipher) {
	t.Helper()
	requested, err := service.RequestEmail(ctx, tokenFixtureEmails[2], tokenFixtureIP, "reports", []accessdomain.PermissionKey{tokenFixturePermission})
	require.NoError(t, err)
	var encrypted []byte
	require.NoError(t, f.db.QueryRow(ctx, `SELECT payload FROM auth.email_login_outbox WHERE digest=$1`, cipher.Digest("native:binding:"+requested.Binding)).Scan(&encrypted))
	plain, err := cipher.Open(encrypted)
	require.NoError(t, err)
	defer clear(plain)
	var mail struct{ Body string }
	require.NoError(t, json.Unmarshal(plain, &mail))
	match := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(mail.Body)
	require.Len(t, match, 2)
	result, err := service.ConfirmEmail(ctx, otpservice.ConfirmInput{Code: match[1], Binding: requested.Binding, IP: tokenFixtureIP, UserAgent: "native email fixture"})
	require.NoError(t, err)
	require.NotNil(t, result.Tokens)
	claims, err := verifier.VerifySignature(ctx, result.Tokens.Raw, time.Now())
	require.NoError(t, err)
	require.Equal(t, tokenFixtureUsers[2], claims.Subject)
	consumer, ok := service.Authenticate(tokenConsumerID, tokenConsumerSecret)
	require.True(t, ok)
	active, err := service.Inspect(ctx, consumer, result.Tokens.Raw)
	require.NoError(t, err)
	require.True(t, active.Active)
	require.NoError(t, service.Logout(ctx, tokenservice.RefreshInput{Token: result.Tokens.RefreshToken, IP: tokenFixtureIP}))
	inactive, err := service.Inspect(ctx, consumer, result.Tokens.Raw)
	require.NoError(t, err)
	require.Equal(t, tokenservice.IntrospectionResult{}, inactive, "logout must revoke online authority")
	rejected, err := service.Refresh(ctx, tokenservice.RefreshInput{Token: result.Tokens.RefreshToken, IP: tokenFixtureIP})
	require.Error(t, err)
	require.Nil(t, rejected)
}
