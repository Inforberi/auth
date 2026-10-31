package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestMFAProjectIsolationSQL(t *testing.T) {
	admin := isolationAdmin(t)
	a := newMFAIsolationRealm(t, isolationDatabase(t, admin, "auth_mfa_isolation_a_test"), "project", "a8100000-0000-4000-8000-000000000001", "https://a.example.test")
	b := newMFAIsolationRealm(t, isolationDatabase(t, admin, "auth_mfa_isolation_b_test"), "project", "a8100000-0000-4000-8000-000000000002", "https://b.example.test")
	platform := newMFAIsolationRealm(t, isolationDatabase(t, admin, "auth_mfa_isolation_platform_test"), "platform", "a8100000-0000-4000-8000-000000000003", "https://platform.example.test")
	t.Run("shared Redis budgets", func(t *testing.T) { checkIsolationMFALimits(t, []mfaIsolationRealm{a, b, platform}) })
	ctx := t.Context()
	var credentials []isolationCredentials
	for _, r := range []mfaIsolationRealm{a, b, platform} {
		cookie, err := r.login.BeginLogin(ctx, r.primary(t, ctx), "isolation", "192.0.2.1")
		require.NoError(t, err)
		require.NotEmpty(t, cookie.RawToken)
		input, claims, raw := r.exchange(t, cookie.RawToken)
		native, err := r.tokens.IssueNative(ctx, tokenservice.NativeInput{Proof: r.primary(t, ctx), Audience: input.Audience, Scope: input.Scope, IP: input.IP})
		require.NoError(t, err)
		credentials = append(credentials, isolationCredentials{realm: r, cookie: cookie.RawToken, input: input, claims: claims, raw: raw, refresh: native.RefreshToken})
	}
	for i, source := range credentials {
		sealed, err := source.realm.cipher.Seal([]byte("MFA isolation fixture"))
		require.NoError(t, err)
		for j, target := range credentials {
			if i == j {
				continue
			}
			_, err := target.realm.cipher.Open(sealed)
			require.Error(t, err, "sharing a root key must not allow cross-realm decryption")
			require.NotEqual(t, source.realm.cipher.Digest("user:"+string(isolationUser)), target.realm.cipher.Digest("user:"+string(isolationUser)))
			_, err = sessionpostgres.New(target.realm.db).FindSession(ctx, tokengenerate.New().Hash(source.cookie))
			require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
			_, err = target.realm.tokens.Exchange(ctx, source.input)
			require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
			_, err = target.realm.verifier.VerifySignature(ctx, source.raw, time.Now())
			require.ErrorIs(t, err, authjwt.ErrInvalidToken)
			_, err = tokenpostgres.New(target.realm.db).Introspect(ctx, source.claims, source.input.Scope)
			require.ErrorIs(t, err, authjwt.ErrInvalidToken)
			_, err = target.realm.tokens.Refresh(ctx, tokenservice.RefreshInput{Token: source.refresh, IP: source.input.IP})
			require.ErrorIs(t, err, tokendomain.ErrInvalidRefresh)
			cfg := source.realm.db.Config().ConnConfig.Copy()
			cfg.Database = target.realm.db.Config().ConnConfig.Database
			foreign, err := pgx.ConnectConfig(ctx, cfg)
			if foreign != nil {
				require.NoError(t, foreign.Close(ctx))
			}
			require.Error(t, err, "a project database credential must not connect to its neighbor")
		}
	}
	// Reject a foreign issuer even if a consumer accidentally supplies that issuer's public key.
	wrongIssuer, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: b.issuer, Audience: "orders", Mode: authjwt.Strict}, a.keys, time.Now())
	require.NoError(t, err)
	_, err = wrongIssuer.VerifySignature(ctx, credentials[0].raw, time.Now())
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)
	beforeB, beforePlatform := b.snapshot(t, ctx), platform.snapshot(t, ctx)
	unchanged := func() {
		t.Helper()
		require.Equal(t, beforeB, b.snapshot(t, ctx))
		require.Equal(t, beforePlatform, platform.snapshot(t, ctx))
		for _, c := range credentials[1:] {
			_, err := sessionpostgres.New(c.realm.db).FindSession(ctx, tokengenerate.New().Hash(c.cookie))
			require.NoError(t, err)
			scope, err := tokenpostgres.New(c.realm.db).Introspect(ctx, c.claims, c.input.Scope)
			require.NoError(t, err)
			require.Equal(t, c.input.Scope, scope)
		}
	}
	updateMFATokenRequirement(t, a.db, ctx, a.actor, isolationUser, "realm", true)
	_, err = a.tokens.Exchange(ctx, credentials[0].input)
	require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
	_, err = tokenpostgres.New(a.db).Introspect(ctx, credentials[0].claims, credentials[0].input.Scope)
	require.ErrorIs(t, err, authjwt.ErrInvalidToken)
	_, err = a.tokens.Refresh(ctx, tokenservice.RefreshInput{Token: credentials[0].refresh, IP: "192.0.2.1"})
	require.ErrorIs(t, err, tokendomain.ErrInvalidRefresh)
	unchanged()
	limited, err := a.login.BeginLogin(ctx, a.primary(t, ctx), "isolation", "192.0.2.1")
	require.NoError(t, err)
	require.Empty(t, limited.RawToken)
	require.NotNil(t, limited.Challenge)
	bound := mfaservice.LoginEnrollmentInput{Challenge: limited.Challenge.Token, Binding: limited.Challenge.Binding, IP: "192.0.2.1"}
	for _, peer := range []mfaIsolationRealm{b, platform} {
		_, err := peer.mfa.StartRequiredEnrollment(ctx, bound)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		_, err = peer.mfa.Complete(ctx, mfaservice.CompleteLoginInput{Token: bound.Challenge, Binding: bound.Binding, Code: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Recovery: true, IP: bound.IP})
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	}
	unchanged()
	updateMFATokenRequirement(t, a.db, ctx, a.actor, isolationUser, "role", true)
	updateMFATokenRequirement(t, a.db, ctx, a.actor, isolationUser, "realm", false)
	limited, err = a.login.BeginLogin(ctx, a.primary(t, ctx), "isolation", "192.0.2.1")
	require.NoError(t, err)
	require.NotNil(t, limited.Challenge, "the role still requires MFA after relaxing realm policy")
	require.True(t, limited.Challenge.EnrollmentRequired)
	bound.Challenge, bound.Binding = limited.Challenge.Token, limited.Challenge.Binding
	enrollment, err := a.mfa.StartRequiredEnrollment(ctx, bound)
	require.NoError(t, err)
	codes, err := a.mfa.ConfirmRequiredEnrollment(ctx, mfaservice.ConfirmLoginEnrollmentInput{LoginEnrollmentInput: bound, Token: enrollment.Token, Code: mfaCode(t, a.db, ctx, enrollment.Secret, 0)})
	require.NoError(t, err)
	strong := a.complete(t, codes.Codes[0])
	strong.Token = a.confirmPassword(t, ctx, strong.Token)
	proof := mfaservice.Proof{UserID: isolationUser, TokenHash: tokengenerate.New().Hash(strong.Token), AuthVersion: a.primary(t, ctx).AuthVersion}
	require.ErrorIs(t, mfapostgres.New(a.db).Disable(ctx, proof), mfadomain.ErrRequiredByPolicy)
	unchanged()
	updateMFATokenRequirement(t, a.db, ctx, a.actor, isolationUser, "role", false)
	strong = a.complete(t, codes.Codes[1])
	strong.Token = a.confirmPassword(t, ctx, strong.Token)
	_, strongClaims, _ := a.exchange(t, strong.Token)
	require.NotNil(t, strongClaims.MFATime)
	proof.TokenHash = tokengenerate.New().Hash(strong.Token)
	require.NoError(t, mfapostgres.New(a.db).Disable(ctx, proof))
	_, err = sessionpostgres.New(a.db).FindSession(ctx, proof.TokenHash)
	require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
	unchanged()
	optional, err := a.login.BeginLogin(ctx, a.primary(t, ctx), "isolation", "192.0.2.1")
	require.NoError(t, err)
	require.NotEmpty(t, optional.RawToken)
	require.Nil(t, optional.Challenge)
	for _, c := range credentials[1:] {
		_, err := c.realm.tokens.Refresh(ctx, tokenservice.RefreshInput{Token: c.refresh, IP: c.input.IP})
		require.NoError(t, err, "neighbor refresh remains usable after all changes in A")
	}
}

type isolationCredentials struct {
	realm   mfaIsolationRealm
	cookie  string
	input   tokenservice.ExchangeInput
	claims  authjwt.Claims
	raw     string
	refresh string
}

func (r mfaIsolationRealm) complete(t *testing.T, recovery string) *mfaservice.LoginSession {
	t.Helper()
	ctx := t.Context()
	result, err := r.login.BeginLogin(ctx, r.primary(t, ctx), "isolation", "192.0.2.1")
	require.NoError(t, err)
	require.Empty(t, result.RawToken)
	require.NotNil(t, result.Challenge)
	require.False(t, result.Challenge.EnrollmentRequired)
	completed, err := r.mfa.Complete(ctx, mfaservice.CompleteLoginInput{
		Token: result.Challenge.Token, Binding: result.Challenge.Binding, Code: recovery, Recovery: true, IP: "192.0.2.1",
	})
	require.NoError(t, err)
	return completed
}

func (r mfaIsolationRealm) confirmPassword(t *testing.T, ctx context.Context, current string) string {
	t.Helper()
	tokens := tokengenerate.New()
	replacement, err := tokens.GenerateToken()
	require.NoError(t, err)
	// The fixture supplies the checked password hash; use the real confirmation/rotation transaction.
	_, err = sessionpostgres.New(r.db).ConfirmPassword(ctx, isolationUser, tokens.Hash(current), "old-hash", r.primary(t, ctx).AuthVersion, tokens.Hash(replacement))
	require.NoError(t, err)
	return replacement
}
