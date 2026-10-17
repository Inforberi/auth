package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func deleteFixture(ctx context.Context, f statusFixture, version accountdomain.AuthVersion) (accountdomain.AuthVersion, error) {
	return accountservice.NewDeletion(f.accounts).Delete(ctx, accountdomain.AccountDeletion{UserID: f.user, ActorID: f.actor, ExpectedVersion: version})
}

func assertDeletedAccount(t *testing.T, db *pgxpool.Pool, ctx context.Context, f statusFixture) {
	t.Helper()
	assertInactiveAccount(t, ctx, f)
	var safe bool
	if err := db.QueryRow(ctx, `SELECT status='blocked' AND deleted_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.user_profile WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.email_changes WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=$1 AND (revoked_at IS NULL OR user_agent<>'' OR ip_address<>''))
		AND NOT EXISTS(SELECT 1 FROM auth.user_emails WHERE user_id=$1 AND verified_at IS NOT NULL)
		FROM auth.users WHERE id=$1`, f.user).Scan(&safe); err != nil || !safe {
		t.Fatal("deletion incomplete", safe, err)
	}
}

func checkAccountDeletion(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("cleanup-and-reservation", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "delete-cleanup")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.user_profile SET display_name='Owner',phone_number='+1234567890' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.sessions SET user_agent='private agent',ip_address='192.0.2.1' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		digest := tokengenerate.New().Hash("delete-reset")
		if err := f.passwords.IssueReset(ctx, f.email, passworddomain.ResetChallenge{Digest: digest, Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		var emailID accountdomain.AddressID
		if err := db.QueryRow(ctx, `SELECT id FROM auth.user_emails WHERE user_id=$1`, f.user).Scan(&emailID); err != nil {
			t.Fatal(err)
		}
		verification := tokengenerate.New().Hash("delete-verification")
		if _, err := db.Exec(ctx, `INSERT INTO auth.email_verifications(digest,email_id,expires_at) VALUES ($1,$2,clock_timestamp()+interval '1 hour')`, verification, emailID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO auth.email_verification_outbox(digest,payload,expires_at) VALUES ($1,$2,clock_timestamp()+interval '1 hour')`, verification, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		version, err := deleteFixture(ctx, f.statusFixture, 1)
		if err != nil || version != 2 {
			t.Fatal(version, err)
		}
		assertDeletedAccount(t, db, ctx, f.statusFixture)
		if err := f.passwords.ConsumeReset(ctx, digest, "replacement"); !errors.Is(err, passworddomain.ErrInvalidReset) {
			t.Fatal("reset revived deleted user", err)
		}
		if err := f.accounts.Confirm(ctx, verification); !errors.Is(err, accountdomain.ErrInvalidVerification) {
			t.Fatal("verification survived", err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("change survived", err)
		}
		if _, err := f.change(ctx, accountdomain.StatusActive, 2); !errors.Is(err, accountdomain.ErrAccountDeleted) {
			t.Fatal("unblock restored deletion", err)
		}
		if _, err := f.passwords.CreateUser(ctx, f.email, "replacement"); !errors.Is(err, passworddomain.ErrEmailAlreadyExists) {
			t.Fatal("reserved contact reused", err)
		}
		if _, err := deleteFixture(ctx, f.statusFixture, 1); !errors.Is(err, accountdomain.ErrAccountConflict) {
			t.Fatal("stale retry", err)
		}
		if version, err := deleteFixture(ctx, f.statusFixture, 2); err != nil || version != 2 {
			t.Fatal("idempotent retry", version, err)
		}
		var audit, payloads int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.account_deletion_audit WHERE user_id=$1),
			(SELECT count(*) FROM auth.password_reset_outbox WHERE digest=$2)+(SELECT count(*) FROM auth.email_verification_outbox WHERE digest=$3)`, f.user, digest, verification).Scan(&audit, &payloads); err != nil || audit != 1 || payloads != 0 {
			t.Fatal("audit/cleanup", audit, payloads, err)
		}
	})
	t.Run("audit-rollback", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "delete-rollback")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		input := accountdomain.AccountDeletion{UserID: f.user, ActorID: "33333333-3333-4333-8333-333333333333", ExpectedVersion: 1}
		if _, err := accountservice.NewDeletion(f.accounts).Delete(ctx, input); err == nil {
			t.Fatal("invalid audit actor committed")
		}
		assertChangeLogin(t, ctx, f, f.email, 1)
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
			t.Fatal("rollback revoked session", err)
		}
		var intact bool
		if err := db.QueryRow(ctx, `SELECT deleted_at IS NULL AND EXISTS(SELECT 1 FROM auth.email_changes WHERE user_id=$1 AND state='pending') FROM auth.users WHERE id=$1`, f.user).Scan(&intact); err != nil || !intact {
			t.Fatal("partial deletion", intact, err)
		}
	})
	t.Run("races", func(t *testing.T) {
		for _, action := range []string{"issuance", "recovery", "duplicate", "unblock"} {
			f := protectedFixture(t, db, ctx, "delete-"+action)
			deletion := func() error { _, err := deleteFixture(ctx, f.statusFixture, 3); return err }
			other := func() error {
				switch action {
				case "issuance":
					_, err := f.sessions.CreateSession(ctx, f.params)
					return err
				case "recovery":
					return f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement")
				case "duplicate":
					return deletion()
				default:
					_, err := f.change(ctx, accountdomain.StatusActive, 3)
					return err
				}
			}
			deletionErr, otherErr := protectionPair(deletion, other)
			if errors.Is(deletionErr, accountdomain.ErrAccountConflict) && otherErr == nil && action == "duplicate" {
				deletionErr, otherErr = otherErr, deletionErr
			}
			if errors.Is(deletionErr, accountdomain.ErrAccountConflict) && otherErr == nil && (action == "recovery" || action == "unblock") {
				if _, err := deleteFixture(ctx, f.statusFixture, 4); err != nil {
					t.Fatal("explicit version retry", err)
				}
			} else if deletionErr != nil {
				t.Fatal(action, deletionErr, otherErr)
			}
			if action == "issuance" && !errors.Is(otherErr, sessiondomain.ErrSessionNotFound) {
				t.Fatal("blocked issuance", otherErr)
			}
			if action == "duplicate" && !errors.Is(otherErr, accountdomain.ErrAccountConflict) {
				t.Fatal("duplicate deletion", otherErr)
			}
			if action == "recovery" && otherErr != nil && !errors.Is(otherErr, accountdomain.ErrInvalidAccountRecovery) {
				t.Fatal(otherErr)
			}
			if action == "unblock" && otherErr != nil && !errors.Is(otherErr, accountdomain.ErrAccountDeleted) {
				t.Fatal(otherErr)
			}
			assertDeletedAccount(t, db, ctx, f.statusFixture)
			if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
				t.Fatal("recovery survived deletion", err)
			}
		}
	})
	t.Run("verification-races", func(t *testing.T) {
		for _, action := range []string{"confirm", "resend"} {
			f := newStatusFixture(t, db, ctx, "delete-verification-"+action)
			digest := tokengenerate.New().Hash("delete-verification-" + action)
			proof := accountdomain.Verification{Digest: digest, Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
			if err := f.accounts.Issue(ctx, f.email, proof, 0); err != nil {
				t.Fatal(err)
			}
			deletion := func() error { _, err := deleteFixture(ctx, f, 1); return err }
			other := func() error {
				if action == "confirm" {
					return f.accounts.Confirm(ctx, digest)
				}
				return f.accounts.Issue(ctx, f.email, proof, 0)
			}
			deleteErr, verificationErr := protectionPair(deletion, other)
			if deleteErr != nil {
				t.Fatal(deleteErr)
			}
			if verificationErr != nil && (action != "confirm" || !errors.Is(verificationErr, accountdomain.ErrInvalidVerification)) {
				t.Fatal("verification race", verificationErr)
			}
			assertDeletedAccount(t, db, ctx, f)
			if err := f.accounts.Confirm(ctx, digest); !errors.Is(err, accountdomain.ErrInvalidVerification) {
				t.Fatal("late verification", err)
			}
		}
	})
	t.Run("active-session-issuance", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "delete-active-issuance")
		f.params.TokenHash = tokengenerate.New().Hash("delete-new-session")
		deletion := func() error { _, err := deleteFixture(ctx, f, 1); return err }
		deleteErr, issueErr := protectionPair(deletion, func() error { _, err := f.sessions.CreateSession(ctx, f.params); return err })
		if deleteErr != nil || (issueErr != nil && !errors.Is(issueErr, sessiondomain.ErrSessionNotFound)) {
			t.Fatal(deleteErr, issueErr)
		}
		assertDeletedAccount(t, db, ctx, f)
	})
}
