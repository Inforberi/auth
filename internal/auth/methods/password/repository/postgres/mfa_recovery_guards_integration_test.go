package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
)

func checkMFARecoveryCompletionGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context, op *mfapostgres.Repository) {
	for _, name := range []string{"unapproved", "wrong-request", "wrong-browser", "cancelled", "expired", "new-primary", "normal-login", "version", "blocked", "deleted", "password-changed", "policy", "operator-revoked", "operator-disabled", "attempts"} {
		t.Run(name, func(t *testing.T) {
			f := prepareLostFactor(t, db, ctx, name, false)
			if name != "unapproved" {
				if err := op.DecideRecovery(ctx, f.decision); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "wrong-request":
				f.input.RequestID = "99999999-9999-4999-8999-999999999999"
			case "wrong-browser":
				f.input.Binding = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			case "cancelled":
				f.decision.Approve = false
				if err := op.DecideRecovery(ctx, f.decision); err != nil {
					t.Fatal(err)
				}
			case "expired":
				accessExec(t, db, ctx, `UPDATE auth.mfa_recovery_requests SET created_at=statement_timestamp()-interval '6 minutes',approved_at=statement_timestamp()-interval '6 minutes',expires_at=statement_timestamp()-interval '1 minute' WHERE user_id=$1`, f.user)
			case "new-primary":
				_ = f.start(t, ctx)
			case "normal-login":
				if _, err := f.login.Complete(ctx, mfaservice.CompleteLoginInput{Token: f.input.Token, Binding: f.input.Binding, Code: f.codes[0], Recovery: true, IP: f.input.IP}); err != nil {
					t.Fatal(err)
				}
			case "version":
				accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=3 WHERE id=$1`, f.user)
			case "blocked":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
			case "deleted":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`, f.user)
			case "password-changed":
				accessExec(t, db, ctx, `UPDATE auth.password_credentials SET password_hash='changed' WHERE user_id=$1`, f.user)
			case "policy":
				f.svc = recoveryService(t, db, func(string, string) bool { return false })
			case "operator-revoked":
				accessExec(t, db, ctx, `REVOKE auth_mfa_recovery_operator FROM auth_mfa_completion_operator`)
				t.Cleanup(func() { accessExec(t, db, ctx, `GRANT auth_mfa_recovery_operator TO auth_mfa_completion_operator`) })
			case "operator-disabled":
				accessExec(t, db, ctx, `ALTER ROLE auth_mfa_completion_operator NOLOGIN`)
				t.Cleanup(func() { accessExec(t, db, ctx, `ALTER ROLE auth_mfa_completion_operator LOGIN`) })
			case "attempts":
				f.input.Code = wrongRecoveryCode(t, db, ctx, f.candidate.Secret)
				for range 5 {
					if _, err := f.svc.Complete(ctx, f.input); !errors.Is(err, mfadomain.ErrInvalidCode) {
						t.Fatal("incorrect TOTP", err)
					}
				}
				f.input.Code = mfaCode(t, db, ctx, f.candidate.Secret, 0)
			}
			if result, err := f.svc.Complete(ctx, f.input); !errors.Is(err, mfadomain.ErrInvalidCode) || result != nil {
				t.Fatal("guard bypass", name, err)
			}
			var encrypted []byte
			if err := db.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&encrypted); err != nil {
				t.Fatal(err)
			}
			plain, err := recoveryCipher(t).Open(encrypted)
			if err != nil || string(plain) != string(f.user)+"\x00"+f.secret {
				t.Fatal("old factor changed", err)
			}
			clear(plain)
			var attempts int
			if name == "attempts" || name == "unapproved" || name == "wrong-browser" || name == "wrong-request" {
				if err := db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_recovery_requests WHERE user_id=$1`, f.user).Scan(&attempts); err != nil {
					t.Fatal(err)
				}
				want := 0
				if name == "attempts" {
					want = 5
				}
				if attempts != want {
					t.Fatal("committed attempt bound", attempts, want)
				}
			}
		})
	}
	t.Run("external-only-no-verified-contact", func(t *testing.T) {
		// The initialized installation requires a versioned managed-provider proof.
		accessExec(t, db, ctx, `INSERT INTO auth.provider_settings(provider,client_id,secret,secret_set)
			VALUES('google','fixture.apps.googleusercontent.com',$1,true)`, make([]byte, 48))
		f := prepareLostFactor(t, db, ctx, "external", false)
		accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,'https://accounts.google.com','recovery-external')`, f.user)
		accessExec(t, db, ctx, `DELETE FROM auth.password_credentials WHERE user_id=$1`, f.user)
		f.proof.Method, f.proof.Issuer, f.proof.Reference = "oidc", "https://accounts.google.com", "recovery-external"
		f.proof.ProviderVersion = 1
		primary := f.start(t, ctx)
		f.svc = recoveryService(t, db, func(method, issuer string) bool { return method == "oidc" && issuer == "https://accounts.google.com" })
		candidate, err := f.svc.Start(ctx, mfaservice.StartRecoveryInput{Token: primary.Token, Binding: primary.Binding, IP: primary.IP})
		if err != nil {
			t.Fatal(err)
		}
		f.decision.RequestID = candidate.RequestID
		if err := op.DecideRecovery(ctx, f.decision); err != nil {
			t.Fatal(err)
		}
		input := mfaservice.CompleteRecoveryInput{RequestID: candidate.RequestID, Token: primary.Token, Binding: primary.Binding, Code: mfaCode(t, db, ctx, candidate.Secret, 0), IP: primary.IP}
		accessExec(t, db, ctx, `DELETE FROM auth.linked_identities WHERE user_id=$1`, f.user)
		if _, err := f.svc.Complete(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("revoked identity accepted", err)
		}
		accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,'https://accounts.google.com','recovery-external')`, f.user)
		if _, err := f.svc.Complete(ctx, input); err != nil {
			t.Fatal("external completion", err)
		}
		var correct bool
		if err := db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1)
			AND NOT EXISTS(SELECT 1 FROM auth.user_emails WHERE user_id=$1 AND verified_at IS NOT NULL)
			AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_outbox WHERE user_id=$1)
			AND EXISTS(SELECT 1 FROM auth.mfa_audit WHERE user_id=$1 AND event='recovery_completed' AND NOT notification_queued)`, f.user).Scan(&correct); err != nil || !correct {
			t.Fatal("unverified notification/password provisioned", err)
		}
	})
	t.Run("recreated-operator", func(t *testing.T) {
		f := prepareLostFactor(t, db, ctx, "recreated-operator", false)
		if err := op.DecideRecovery(ctx, f.decision); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `DROP ROLE auth_mfa_completion_operator;
			CREATE ROLE auth_mfa_completion_operator LOGIN PASSWORD 'synthetic-recovery-only';
			GRANT auth_mfa_recovery_operator TO auth_mfa_completion_operator`)
		if _, err := f.svc.Complete(ctx, f.input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("new login inherited old approval", err)
		}
	})
}

func wrongRecoveryCode(t *testing.T, db *pgxpool.Pool, ctx context.Context, secret string) string {
	t.Helper()
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		code := fmt.Sprintf("%06d", i)
		if _, err := (mfatotp.Authenticator{}).Match(secret, code, now, -1); errors.Is(err, mfadomain.ErrInvalidCode) {
			return code
		}
	}
	t.Fatal("cannot choose incorrect TOTP")
	return ""
}
