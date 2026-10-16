package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func checkMFALoginGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for _, state := range []string{"expired", "blocked", "deleted", "version", "credentials", "factor-removed"} {
		t.Run(state, func(t *testing.T) {
			f := newMFALoginFixture(t, db, ctx, state)
			input := f.start(t, ctx)
			switch state {
			case "expired":
				accessExec(t, db, ctx, `UPDATE auth.mfa_login_challenges SET primary_verified_at=statement_timestamp()-interval '10 minutes',
					created_at=statement_timestamp()-interval '10 minutes',expires_at=statement_timestamp()-interval '5 minutes' WHERE user_id=$1`, f.user)
			case "blocked":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
			case "deleted":
				if _, err := deleteFixture(ctx, f.statusFixture, 2); err != nil {
					t.Fatal(err)
				}
			case "version":
				accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, f.user)
			case "credentials":
				accessExec(t, db, ctx, `UPDATE auth.password_credentials SET password_hash='another-hash' WHERE user_id=$1`, f.user)
			case "factor-removed":
				accessExec(t, db, ctx, `DELETE FROM auth.mfa_totp WHERE user_id=$1`, f.user)
			}
			if result, err := f.login.Complete(ctx, input); result != nil || !errors.Is(err, mfadomain.ErrInvalidCode) {
				t.Fatal("stale authority accepted", state, err)
			}
		})
	}
	t.Run("primary-proof", func(t *testing.T) {
		f := newMFALoginFixture(t, db, ctx, "primary")
		nearFuture := f.proof
		nearFuture.VerifiedAt = time.Now().Add(2 * time.Second)
		if _, err := f.login.Start(ctx, nearFuture, "192.0.2.1"); err != nil {
			t.Fatal("bounded backend clock skew", err)
		}
		var bounded bool
		if err := db.QueryRow(ctx, `SELECT primary_verified_at<=created_at FROM auth.mfa_login_challenges WHERE user_id=$1`, f.user).Scan(&bounded); err != nil || !bounded {
			t.Fatal("future authentication timestamp", err)
		}
		for _, state := range []string{"stale", "future", "hash", "foreign", "version"} {
			proof := f.proof
			switch state {
			case "stale":
				proof.VerifiedAt = time.Now().Add(-2 * time.Minute)
			case "future":
				proof.VerifiedAt = time.Now().Add(time.Hour)
			case "hash":
				proof.Reference = "not-the-verified-hash"
			case "foreign":
				proof.UserID = f.actor
			case "version":
				proof.AuthVersion = 1
			}
			if result, err := f.login.Start(ctx, proof, "192.0.2.1"); result != nil || !errors.Is(err, mfadomain.ErrProofRequired) {
				t.Fatal("invalid primary accepted", state, err)
			}
		}
	})
	for _, method := range []string{"oidc", "emailotp"} {
		t.Run(method+"-binding", func(t *testing.T) {
			f := newMFALoginFixture(t, db, ctx, method)
			f.proof.Method = method
			if method == "oidc" {
				f.proof.Issuer, f.proof.Reference = "https://accounts.google.com", "subject-"+string(f.user)
				accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) VALUES ($1,$2,$3)`, f.proof.Issuer, f.proof.Reference, f.user)
			} else {
				accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
				if err := db.QueryRow(ctx, `SELECT email_id FROM auth.password_credentials WHERE user_id=$1`, f.user).Scan(&f.proof.Reference); err != nil {
					t.Fatal(err)
				}
			}
			input := f.start(t, ctx)
			if _, err := f.login.Complete(ctx, input); err != nil {
				t.Fatal(err)
			}
			input = f.start(t, ctx)
			input.Code = f.codes[1]
			if method == "oidc" {
				accessExec(t, db, ctx, `DELETE FROM auth.linked_identities WHERE user_id=$1`, f.user)
			} else {
				accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, f.user)
			}
			if _, err := f.login.Complete(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
				t.Fatal("changed primary accepted", err)
			}
		})
	}
}

func checkMFALoginRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for _, failure := range []string{"audit", "session", "totp-session"} {
		t.Run(failure, func(t *testing.T) {
			f := newMFALoginFixture(t, db, ctx, "rollback-"+failure)
			input := f.start(t, ctx)
			var initialStep int64
			if err := db.QueryRow(ctx, `SELECT last_step FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&initialStep); err != nil {
				t.Fatal(err)
			}
			if failure == "totp-session" {
				input.Recovery = false
				input.Code = mfaCode(t, db, ctx, f.secret, 30*time.Second)
			}
			table, predicate := "auth.sessions", "TRUE"
			if failure == "audit" {
				table, predicate = "auth.mfa_audit", "NEW.event='mfa_login_completed'"
			}
			accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_mfa_login_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
				IF `+predicate+` THEN RAISE EXCEPTION 'commit unavailable'; END IF; RETURN NEW; END; $$;
				CREATE TRIGGER reject_mfa_login_commit BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION auth.reject_mfa_login_commit()`)
			result, err := f.login.Complete(ctx, input)
			accessExec(t, db, ctx, `DROP TRIGGER reject_mfa_login_commit ON `+table+`; DROP FUNCTION auth.reject_mfa_login_commit()`)
			if result != nil || err == nil {
				t.Fatal("partial commit accepted")
			}
			var afterStep int64
			if err := db.QueryRow(ctx, `SELECT last_step FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&afterStep); err != nil || afterStep != initialStep {
				t.Fatal("rollback burned TOTP step", afterStep, initialStep, err)
			}
			var codes, challenges, sessions, audits int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1),
				(SELECT count(*) FROM auth.mfa_login_challenges WHERE user_id=$1 AND attempts=0),
				(SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL),
				(SELECT count(*) FROM auth.mfa_audit WHERE user_id=$1 AND event='recovery_used')`, f.user).
				Scan(&codes, &challenges, &sessions, &audits); err != nil || codes != 10 || challenges != 1 || sessions != 0 || audits != 0 {
				t.Fatal("incomplete rollback", codes, challenges, sessions, audits, err)
			}
			if _, err := f.login.Complete(ctx, input); err != nil {
				t.Fatal("retry after full rollback", err)
			}
		})
	}
}
