package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type changeFixture struct {
	statusFixture
	snapshot accountdomain.EmailChangeSnapshot
	intent   accountdomain.EmailChangeIntent
	newEmail string
}

func newChangeFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) changeFixture {
	t.Helper()
	f := changeFixture{statusFixture: newStatusFixture(t, db, ctx, "change-"+name), newEmail: "new-" + name + "@example.com"}
	f.accounts = accountpostgres.NewWithEmailChanges(db)
	if _, err := db.Exec(ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	var err error
	f.snapshot, err = f.accounts.EmailChangeSnapshot(ctx, f.user)
	if err != nil {
		t.Fatal(err)
	}
	hash := tokengenerate.New()
	f.intent = accountdomain.EmailChangeIntent{ConfirmDigest: hash.Hash("confirm-" + name), ReportDigest: hash.Hash("report-" + name), ConfirmPayload: make([]byte, 32), NoticePayload: make([]byte, 32), CompletionPayload: make([]byte, 32), RecoveryDigest: hash.Hash("recover-" + name), RecoveryPayload: make([]byte, 32), RecoveryTTL: 30 * time.Minute, ExpiresAt: time.Now().Add(30 * time.Minute), ProtectUntil: time.Now().Add(24 * time.Hour)}
	return f
}

func (f changeFixture) request(ctx context.Context) error {
	return f.accounts.RequestEmailChange(ctx, f.snapshot, f.params.TokenHash, f.newEmail, f.intent)
}

func assertChangeLogin(t *testing.T, ctx context.Context, f changeFixture, email string, version int64) {
	t.Helper()
	credential, err := f.passwords.FindByEmail(ctx, email)
	if err != nil || credential.AuthVersion != version {
		t.Fatal("login/version", credential, err)
	}
}

func checkEmailChange(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("confirm-and-report", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "confirmed")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		assertChangeLogin(t, ctx, f, f.email, 1)
		if _, err := f.passwords.FindByEmail(ctx, f.newEmail); !errors.Is(err, passworddomain.ErrUserNotFound) {
			t.Fatal("new login became active early", err)
		}
		if err := f.request(ctx); !errors.Is(err, accountdomain.ErrEmailChangePending) {
			t.Fatal("pending token replaced", err)
		}
		reset := passworddomain.ResetChallenge{Digest: tokengenerate.New().Hash("change-reset"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.passwords.IssueReset(ctx, f.email, reset); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ReportDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("report token confirmed", err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		assertChangeLogin(t, ctx, f, f.newEmail, 2)
		if _, err := f.passwords.FindByEmail(ctx, f.email); !errors.Is(err, passworddomain.ErrUserNotFound) {
			t.Fatal("old email still login", err)
		}
		occupied, err := f.passwords.ExistsByEmail(ctx, f.email)
		if err != nil || !occupied {
			t.Fatal("old verified contact released", err)
		}
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("session survived change", err)
		}
		if err := f.passwords.ConsumeReset(ctx, reset.Digest, "new-hash"); !errors.Is(err, passworddomain.ErrInvalidReset) {
			t.Fatal("old reset survived change", err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("confirmation replay", err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
			t.Fatal("security token lost after confirm", err)
		}
		assertInactiveAccount(t, ctx, f.statusFixture)
		var email, state string
		if err := db.QueryRow(ctx, `SELECT e.email,c.state FROM auth.password_credentials p JOIN auth.user_emails e ON e.id=p.email_id JOIN auth.email_changes c ON c.user_id=p.user_id WHERE p.user_id=$1`, f.user).Scan(&email, &state); err != nil || email != f.newEmail || state != "reported" {
			t.Fatal("automatic rollback or missing report", email, state, err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("security replay", err)
		}
	})
	t.Run("cancel-before-confirm", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "cancel")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
			t.Fatal(err)
		}
		assertChangeLogin(t, ctx, f, f.email, 2)
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("cancelled change completed", err)
		}
		if err := f.sessions.CreateSession(ctx, f.params); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("stale issuance after cancellation", err)
		}
	})
	t.Run("ownership-race", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "occupied")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.passwords.CreateUser(ctx, f.newEmail, "other-hash"); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("occupied address claimed", err)
		}
		assertChangeLogin(t, ctx, f, f.email, 1)
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
			t.Fatal("ownership failure changed sessions", err)
		}
	})
	t.Run("unverified", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "change-unverified")
		if _, err := f.accounts.EmailChangeSnapshot(ctx, f.user); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
			t.Fatal("unverified old address admitted", err)
		}
	})
	t.Run("stale-password-snapshot", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "stale")
		if _, err := db.Exec(ctx, `UPDATE auth.password_credentials SET password_hash='changed-hash' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if err := f.request(ctx); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
			t.Fatal("stale password accepted", err)
		}
	})
	t.Run("expiry-and-session", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "expiry")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_changes SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("expired confirmation", err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
			t.Fatal("unexpired security window lost", err)
		}
		f = newChangeFixture(t, db, ctx, "session-expiry")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
			t.Fatal("revoked session completed change", err)
		}
	})
	t.Run("block-unblock-clears-change", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "block")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := f.change(ctx, accountdomain.StatusActive, 2); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("change revived after unblock", err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal("old security token survived unblock", err)
		}
	})
	t.Run("atomic-rollback", func(t *testing.T) { checkChangeRollback(t, db, ctx) })
	t.Run("races", func(t *testing.T) { checkChangeRaces(t, db, ctx) })
	t.Run("delivery", func(t *testing.T) { checkChangeDelivery(t, db, ctx) })
}

func checkChangeRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	f := newChangeFixture(t, db, ctx, "rollback")
	if err := f.request(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_change_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
		CREATE TRIGGER reject_change_audit BEFORE INSERT ON auth.email_change_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_change_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err == nil {
		t.Fatal("change committed without audit")
	}
	assertChangeLogin(t, ctx, f, f.email, 1)
	if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
		t.Fatal("rollback lost session", err)
	}
	if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err == nil {
		t.Fatal("report committed without audit")
	}
	assertChangeLogin(t, ctx, f, f.email, 1)
	if _, err := db.Exec(ctx, `DROP TRIGGER reject_change_audit ON auth.email_change_audit;DROP FUNCTION auth.reject_change_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_change_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'outbox unavailable'; END; $$;
		CREATE TRIGGER reject_change_outbox BEFORE INSERT ON auth.email_change_outbox FOR EACH ROW EXECUTE FUNCTION auth.reject_change_outbox()`); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err == nil {
		t.Fatal("change committed without notification")
	}
	assertChangeLogin(t, ctx, f, f.email, 1)
	if _, err := db.Exec(ctx, `DROP TRIGGER reject_change_outbox ON auth.email_change_outbox;DROP FUNCTION auth.reject_change_outbox()`); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
		t.Fatal("rollback consumed token", err)
	}
}

func checkChangeRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for attempt := range 12 {
		f := newChangeFixture(t, db, ctx, fmt.Sprintf("race-%d", attempt))
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		var confirmErr, reportErr error
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Go(func() { <-start; confirmErr = f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest) })
		wg.Go(func() { <-start; reportErr = f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest) })
		close(start)
		wg.Wait()
		if reportErr != nil {
			t.Fatal("report lost race", reportErr)
		}
		var state, status string
		if err := db.QueryRow(ctx, `SELECT c.state,u.status FROM auth.email_changes c JOIN auth.users u ON u.id=c.user_id WHERE c.user_id=$1`, f.user).Scan(&state, &status); err != nil {
			t.Fatal(err)
		}
		if confirmErr == nil {
			if state != "reported" || status != "blocked" {
				t.Fatal("confirm won without protection", state, status)
			}
		} else if !errors.Is(confirmErr, accountdomain.ErrInvalidEmailChange) || state != "cancelled" || status != "active" {
			t.Fatal("invalid race result", confirmErr, state, status)
		}
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("race kept session", err)
		}
	}
	f := newChangeFixture(t, db, ctx, "two-confirmations")
	if err := f.request(ctx); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { errs <- f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest) })
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("confirmation was not one-time", success)
	}
	// Explicitly prove that token purposes remain separate even when both digest formats are valid.
	if err := f.accounts.ReportEmailChange(ctx, strings.Repeat("0", 64)); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
		t.Fatal(err)
	}
}
