package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestTelegramMFALoginSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	configureTelegramLoginFixture(t, db, ctx)
	t.Run("browser binding guessing one-use and weak assurance", func(t *testing.T) {
		f := newTelegramLoginSQLFixture(t, db, ctx, "browser")
		input := f.start(t, ctx)
		wrong := input
		wrong.Binding, _ = tokengenerate.New().GenerateToken()
		_, err := f.login.Complete(ctx, wrong)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		var attempts int
		require.NoError(t, db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_login_challenges WHERE user_id=$1`, f.user).Scan(&attempts))
		require.Zero(t, attempts)
		wrong = input
		wrong.Code = "123456"
		_, err = f.login.Complete(ctx, wrong)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode, "TOTP cannot satisfy a Telegram challenge")
		result, err := f.login.Complete(ctx, input)
		require.NoError(t, err)
		var method string
		var strong bool
		require.NoError(t, db.QueryRow(ctx, `SELECT mfa_method,strong_mfa_verified_at IS NOT NULL FROM auth.role_bound_sessions WHERE token_hash=$1`, tokengenerate.New().Hash(result.Token)).Scan(&method, &strong))
		require.Equal(t, "telegram", method)
		require.False(t, strong)
		_, err = f.login.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp() WHERE token_hash=$1`, tokengenerate.New().Hash(result.Token))
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='required',version=version+1`)
		t.Cleanup(func() { accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='administrators'`) })
		err = mfapostgres.New(db).DisableTelegramFactor(ctx, mfaservice.FactorMutation{Proof: mfaservice.Proof{UserID: f.user, TokenHash: tokengenerate.New().Hash(result.Token), AuthVersion: f.primary.AuthVersion}})
		require.ErrorIs(t, err, mfadomain.ErrRequiredByPolicy, "fresh Telegram proof cannot remove the last mandatory factor")
	})
	t.Run("delivery failure and late configuration do not issue credentials", func(t *testing.T) {
		f := newTelegramLoginSQLFixture(t, db, ctx, "delivery")
		f.sender.fail = errors.New("synthetic bot token must not leak")
		_, err := f.selector.Start(ctx, f.primary, "192.0.2.1")
		require.ErrorIs(t, err, mfadomain.ErrUnavailable)
		require.NotContains(t, err.Error(), "synthetic")
		var delivered bool
		require.NoError(t, db.QueryRow(ctx, `SELECT delivered_at IS NOT NULL FROM auth.mfa_telegram_login_codes c JOIN auth.mfa_login_challenges p USING(digest) WHERE p.user_id=$1`, f.user).Scan(&delivered))
		require.False(t, delivered)
		f.sender.fail = nil
		f.sender.after = func(ctx context.Context) { accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET version=version+1`) }
		_, err = f.selector.Start(ctx, f.primary, "192.0.2.1")
		require.Error(t, err)
		require.NoError(t, db.QueryRow(ctx, `SELECT delivered_at IS NOT NULL FROM auth.mfa_telegram_login_codes c JOIN auth.mfa_login_challenges p USING(digest) WHERE p.user_id=$1`, f.user).Scan(&delivered))
		require.False(t, delivered)
	})
	t.Run("guess limit expiry and replacement", func(t *testing.T) {
		f := newTelegramLoginSQLFixture(t, db, ctx, "bounds")
		input := f.start(t, ctx)
		wrong := input
		wrong.Code = "00000000"
		if wrong.Code == input.Code {
			wrong.Code = "11111111"
		}
		for range 5 {
			_, err := f.login.Complete(ctx, wrong)
			require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		}
		_, err := f.login.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode, "correct code after five guesses stays rejected")
		input = f.start(t, ctx)
		accessExec(t, db, ctx, `UPDATE auth.mfa_login_challenges SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, f.user)
		_, err = f.login.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		old := f.start(t, ctx)
		current := f.start(t, ctx)
		_, err = f.login.Complete(ctx, old)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		_, err = f.login.Complete(ctx, current)
		require.NoError(t, err, "new intent replaces the old child without FK failure")
	})
	t.Run("native issue refresh and browser separation", func(t *testing.T) {
		f := newTelegramLoginSQLFixture(t, db, ctx, "native")
		accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('telegram_native_reader','Telegram native reader') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'orders.read' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
		signer, keys := jwtSigningFixture(t)
		tokens := nativeTokenService(t, db, signer)
		coordinator, err := tokenservice.NewNativeLogin(tokens, f.selector)
		require.NoError(t, err)
		started, err := coordinator.Begin(ctx, tokenservice.NativeInput{Proof: f.primary, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}, IP: "192.0.2.1"})
		require.NoError(t, err)
		require.Nil(t, started.Tokens)
		input := mfaservice.CompleteLoginInput{Token: started.Challenge.Token, Binding: started.Challenge.Binding, Code: f.sender.code, IP: "192.0.2.1"}
		_, err = f.login.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		accessExec(t, db, ctx, `ALTER TABLE auth.token_issuance_audit ADD CONSTRAINT reject_telegram_native CHECK(false) NOT VALID`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `ALTER TABLE auth.token_issuance_audit DROP CONSTRAINT IF EXISTS reject_telegram_native`)
		})
		_, err = coordinator.Complete(ctx, input)
		require.Error(t, err)
		var partial int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND credential_profile='api'`, f.user).Scan(&partial))
		require.Zero(t, partial)
		accessExec(t, db, ctx, `ALTER TABLE auth.token_issuance_audit DROP CONSTRAINT reject_telegram_native`)
		issued, err := coordinator.Complete(ctx, input)
		require.NoError(t, err)
		verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		require.NoError(t, err)
		claims, err := verifier.VerifySignature(ctx, issued.Raw, time.Now())
		require.NoError(t, err)
		require.Equal(t, []string{"pwd", "telegram_otp"}, claims.Methods)
		refreshed, err := tokens.Refresh(ctx, tokenservice.RefreshInput{Token: issued.RefreshToken, IP: input.IP})
		require.NoError(t, err)
		claims, err = verifier.VerifySignature(ctx, refreshed.Raw, time.Now())
		require.NoError(t, err)
		require.Equal(t, []string{"pwd", "telegram_otp"}, claims.Methods)
		_, err = coordinator.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	})
	t.Run("administrative authority refuses a Telegram proof", func(t *testing.T) {
		f := newTelegramLoginSQLFixture(t, db, ctx, "admin-proof")
		input := f.start(t, ctx)
		accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('telegram_authority_admin','Admin proof') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
		var allowed bool
		require.NoError(t, db.QueryRow(ctx, `SELECT auth.mfa_proof_usable($1,'password','telegram')`, f.user).Scan(&allowed))
		require.False(t, allowed)
		_, err := f.login.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	})
	t.Run("unavailable preference never downgrades", func(t *testing.T) {
		f := newTelegramLoginSQLFixture(t, db, ctx, "preference")
		accessExec(t, db, ctx, `INSERT INTO auth.mfa_preferences(user_id,preferred_method) VALUES($1,'telegram')`, f.user)
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=false`)
		t.Cleanup(func() { accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=true`) })
		_, err := f.selector.Start(ctx, f.primary, "192.0.2.1")
		require.ErrorIs(t, err, mfadomain.ErrUnavailable)
		challenge, err := f.login.Start(ctx, f.primary, "192.0.2.1")
		require.NoError(t, err)
		require.True(t, challenge.RecoveryRequired, "explicit recovery remains possible without delivery")
	})
}
