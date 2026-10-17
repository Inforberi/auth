package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkNativeEmailGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("profile namespace target and replacement", func(t *testing.T) {
		f := newNativeEmailFixture(t, db, ctx)
		input := f.request(t, db, ctx)
		digest, verifier := f.cipher.Digest("native:binding:"+input.Binding), f.cipher.Digest("native:code:"+input.Binding+":"+input.Code)
		if _, err := f.otp.Confirm(ctx, input); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("native accepted by browser service", err)
		}
		repo := otppostgres.New(db)
		if _, err := repo.Consume(ctx, digest, verifier); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("native accepted by browser SQL", err)
		}
		for _, query := range []string{
			`UPDATE auth.email_login_challenges SET native_audience='other' WHERE user_id=$1`,
			`UPDATE auth.email_login_challenges SET native_scope=ARRAY['orders.write'] WHERE user_id=$1`,
			`UPDATE auth.email_login_challenges SET credential_profile='browser',native_audience=NULL,native_scope=NULL WHERE user_id=$1`,
			`UPDATE auth.email_login_challenges SET purpose='reauthenticate',session_hash=repeat('a',64) WHERE user_id=$1`,
		} {
			expectSQLState(t, db, ctx, "P0001", query, f.user)
		}
		browser, err := f.otp.Request(ctx, f.email, input.IP)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.login.Confirm(ctx, input); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("replaced code accepted", err)
		}
		if _, err := repo.ConsumeNative(ctx, f.cipher.Digest("binding:"+browser.Binding), "ignored"); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("browser accepted by native SQL", err)
		}
		input.Binding = browser.Binding
		if _, err := f.otp.AuthenticateNative(ctx, input); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("browser accepted by native service", err)
		}
		assertNativeRows(t, db, ctx, string(f.user), 0)
	})
	for _, test := range []struct {
		name, sql string
		want      error
	}{
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`, otpdomain.ErrInvalidCode},
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, otpdomain.ErrInvalidCode},
		{"unverified", `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, otpdomain.ErrInvalidCode},
		{"expired", `UPDATE auth.email_login_challenges SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE user_id=$1`, otpdomain.ErrInvalidCode},
		{"grant removed", `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, tokendomain.ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newNativeEmailFixture(t, db, ctx)
			input := f.request(t, db, ctx)
			accessExec(t, db, ctx, test.sql, f.user)
			if result, err := f.login.Confirm(ctx, input); result != nil || !errors.Is(err, test.want) {
				t.Fatal("stale email authority issued tokens", err)
			}
			assertNativeRows(t, db, ctx, string(f.user), 0)
		})
	}
	t.Run("audit abort restores email code", func(t *testing.T) {
		f := newNativeEmailFixture(t, db, ctx)
		input := f.request(t, db, ctx)
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_native_email_consume() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='code_consumed' THEN RAISE EXCEPTION 'synthetic consume abort'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_native_email_consume BEFORE INSERT ON auth.email_login_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_native_email_consume()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_native_email_consume ON auth.email_login_audit;DROP FUNCTION auth.reject_native_email_consume()`)
		})
		if result, err := f.login.Confirm(ctx, input); err == nil || result != nil {
			t.Fatal("audit failure issued credentials")
		}
		var intact bool
		if err := db.QueryRow(ctx, `SELECT c.attempts=0 AND EXISTS(SELECT 1 FROM auth.email_login_outbox WHERE digest=c.digest) FROM auth.email_login_challenges c WHERE user_id=$1`, f.user).Scan(&intact); err != nil || !intact {
			t.Fatal("consume rolled back incompletely", err)
		}
		assertNativeRows(t, db, ctx, string(f.user), 0)
	})
	t.Run("sign abort does not restore consumed email code", func(t *testing.T) {
		f := newNativeEmailFixture(t, db, ctx)
		input := f.request(t, db, ctx)
		primary, err := tokenservice.NewNativeLogin(nativeTokenService(t, db, failingRefreshSigner{}), f.mfa)
		if err != nil {
			t.Fatal(err)
		}
		failed, err := tokenservice.NewNativeEmailLogin(primary, f.otp)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := failed.Confirm(ctx, input); result != nil || !errors.Is(err, authjwt.ErrBusy) {
			t.Fatal("signing failure leaked credentials", err)
		}
		if _, err := f.login.Confirm(ctx, input); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("consumed email code resurrected", err)
		}
		assertNativeRows(t, db, ctx, string(f.user), 0)
	})
}

func checkNativeEmailMFA(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("email required enrollment fresh code and MFA", func(t *testing.T) {
		f := newNativeEmailFixture(t, db, ctx)
		accessExec(t, db, ctx, `UPDATE auth.roles SET mfa_required=true WHERE id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, f.user)
		input := f.request(t, db, ctx)
		result, err := f.login.Confirm(ctx, input)
		if err != nil || result.Tokens != nil || result.Challenge == nil || !result.Challenge.EnrollmentRequired {
			t.Fatal("role required enrollment bypassed", err)
		}
		bound := mfaservice.LoginEnrollmentInput{Challenge: result.Challenge.Token, Binding: result.Challenge.Binding, IP: input.IP}
		enrollment, err := f.mfa.StartNativeRequiredEnrollment(ctx, bound)
		if err != nil {
			t.Fatal(err)
		}
		codes, err := f.mfa.ConfirmNativeRequiredEnrollment(ctx, mfaservice.ConfirmLoginEnrollmentInput{LoginEnrollmentInput: bound, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)})
		if err != nil {
			t.Fatal(err)
		}
		assertNativeRows(t, db, ctx, string(f.user), 0)
		input = f.request(t, db, ctx)
		result, err = f.login.Confirm(ctx, input)
		if err != nil || result.Tokens != nil || result.Challenge == nil || result.Challenge.EnrollmentRequired {
			t.Fatal("fresh email proof after enrollment failed", err)
		}
		completion := mfaservice.CompleteLoginInput{Token: result.Challenge.Token, Binding: result.Challenge.Binding, Code: codes.Codes[0], Recovery: true, IP: input.IP}
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, f.user)
		if _, err := f.primary.Complete(ctx, completion); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("MFA accepted stale email proof", err)
		}
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
		tokens, err := f.primary.Complete(ctx, completion)
		if err != nil {
			t.Fatal("email + factor completion failed", err)
		}
		claims := f.verify(t, ctx, tokens, true)
		if claims.AuthVersion != 2 {
			t.Fatal("old enrollment version survived")
		}
	})
}
