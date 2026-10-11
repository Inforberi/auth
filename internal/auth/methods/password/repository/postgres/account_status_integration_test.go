package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type statusFixture struct {
	passwords   *PasswordRepo
	accounts    *accountpostgres.Repository
	status      *accountservice.StatusService
	sessions    *sessionpostgres.Repository
	user, actor accountdomain.UserID
	email       string
	params      sessionservice.CreateSessionParams
}

func newStatusFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) statusFixture {
	t.Helper()
	f := statusFixture{passwords: New(db), accounts: accountpostgres.New(db), sessions: sessionpostgres.New(db), email: "status-" + name + "@example.com"}
	var err error
	f.user, err = f.passwords.CreateUser(ctx, f.email, "old-hash")
	if err != nil {
		t.Fatal(err)
	}
	f.actor, err = f.passwords.CreateUser(ctx, "actor-"+name+"@example.com", "actor-hash")
	if err != nil {
		t.Fatal(err)
	}
	f.status = accountservice.NewStatus(f.accounts)
	now := time.Now().UTC()
	f.params = sessionservice.CreateSessionParams{UserID: f.user, AuthVersion: 1, TokenHash: tokengenerate.New().Hash("status-" + name), CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour)}
	if err := f.sessions.CreateSession(ctx, f.params); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f statusFixture) change(ctx context.Context, status accountdomain.Status, version accountdomain.AuthVersion) (accountdomain.AuthVersion, error) {
	return f.status.Change(ctx, accountdomain.StatusChange{UserID: f.user, ActorID: f.actor, Status: status, ExpectedVersion: version})
}

func checkAccountStatus(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("block-unblock", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "basic")
		verification := accountdomain.Verification{Digest: strings.Repeat("e", 64), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		reset := passworddomain.ResetChallenge{Digest: strings.Repeat("f", 64), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.accounts.Issue(ctx, f.email, verification, 0); err != nil {
			t.Fatal(err)
		}
		if err := f.passwords.IssueReset(ctx, f.email, reset); err != nil {
			t.Fatal(err)
		}
		if version, err := f.change(ctx, accountdomain.StatusBlocked, 1); err != nil || version != 2 {
			t.Fatal("block", version, err)
		}
		assertInactiveAccount(t, ctx, f)
		if err := f.passwords.ChangePassword(ctx, f.user, f.params.TokenHash, "old-hash", "new-hash"); !errors.Is(err, passworddomain.ErrInvalidEmailOrPassword) {
			t.Fatal("blocked password mutation", err)
		}
		if version, err := f.change(ctx, accountdomain.StatusBlocked, 2); err != nil || version != 2 {
			t.Fatal("unchanged status created a transition", err)
		}
		if version, err := f.change(ctx, accountdomain.StatusActive, 2); err != nil || version != 3 {
			t.Fatal("unblock", version, err)
		}
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("unblock revived session", err)
		}
		if err := f.sessions.CreateSession(ctx, f.params); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("old credential snapshot reissued session", err)
		}
		if err := f.accounts.Confirm(ctx, verification.Digest); !errors.Is(err, accountdomain.ErrInvalidVerification) {
			t.Fatal("old verification survived block", err)
		}
		if err := f.passwords.ConsumeReset(ctx, reset.Digest, "new-hash"); !errors.Is(err, passworddomain.ErrInvalidReset) {
			t.Fatal("old reset survived block", err)
		}
		credential, err := f.passwords.FindByEmail(ctx, f.email)
		if err != nil || credential.AuthVersion != 3 {
			t.Fatal("fresh login unavailable", err)
		}
		fresh := f.params
		fresh.AuthVersion = 3
		fresh.TokenHash = tokengenerate.New().Hash("fresh-basic")
		if err := f.sessions.CreateSession(ctx, fresh); err != nil {
			t.Fatal("fresh session refused", err)
		}
		var auditCount, outboxCount int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.account_status_audit WHERE user_id=$1 AND actor_id=$2`, f.user, f.actor).Scan(&auditCount); err != nil || auditCount != 2 {
			t.Fatal("status audit", auditCount, err)
		}
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.password_reset_outbox WHERE digest=$1)+(SELECT count(*) FROM auth.email_verification_outbox WHERE digest=$2)`, reset.Digest, verification.Digest).Scan(&outboxCount); err != nil || outboxCount != 0 {
			t.Fatal("challenge delivery survived", err)
		}
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 1); !errors.Is(err, accountdomain.ErrAccountConflict) {
			t.Fatal("stale status update accepted", err)
		}
	})
	t.Run("audit-rollback", func(t *testing.T) { checkStatusAuditRollback(t, db, ctx) })
	t.Run("deleted", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "deleted")
		if _, err := db.Exec(ctx, `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		assertInactiveAccount(t, ctx, f)
		if _, err := f.change(ctx, accountdomain.StatusActive, 1); !errors.Is(err, accountdomain.ErrAccountDeleted) {
			t.Fatal("deleted account restored", err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "unknown")
		_, err := f.status.Change(ctx, accountdomain.StatusChange{UserID: "00000000-0000-0000-0000-000000000000", ActorID: f.actor, Status: accountdomain.StatusBlocked, ExpectedVersion: 1})
		if !errors.Is(err, accountdomain.ErrAccountNotFound) {
			t.Fatal("unknown account contract", err)
		}
	})
	t.Run("races", func(t *testing.T) { checkStatusRaces(t, db, ctx) })
}

func assertInactiveAccount(t *testing.T, ctx context.Context, f statusFixture) {
	t.Helper()
	if _, err := f.passwords.FindByEmail(ctx, f.email); !errors.Is(err, passworddomain.ErrUserNotFound) {
		t.Fatal("inactive login lookup", err)
	}
	if _, err := f.passwords.FindUserByUserID(ctx, f.user); !errors.Is(err, passworddomain.ErrNotFound) {
		t.Fatal("inactive credential lookup", err)
	}
	if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("inactive session accepted", err)
	}
	if err := f.sessions.CreateSession(ctx, f.params); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("inactive issuance accepted", err)
	}
	management := sessionservice.NewManagement(f.sessions)
	if _, err := management.List(ctx, f.user, f.params.TokenHash, ""); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("inactive session management", err)
	}
}

func checkStatusAuditRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	f := newStatusFixture(t, db, ctx, "rollback")
	reset := passworddomain.ResetChallenge{Digest: tokengenerate.New().Hash("rollback-reset"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
	if err := f.passwords.IssueReset(ctx, f.email, reset); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_status_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
  CREATE TRIGGER reject_status_audit BEFORE INSERT ON auth.account_status_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_status_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.change(ctx, accountdomain.StatusBlocked, 1); err == nil {
		t.Fatal("status changed without audit")
	}
	if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
		t.Fatal("audit rollback lost session", err)
	}
	credential, err := f.passwords.FindByEmail(ctx, f.email)
	if err != nil || credential.AuthVersion != 1 {
		t.Fatal("audit rollback changed account", err)
	}
	var present bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_resets WHERE digest=$1)`, reset.Digest).Scan(&present); err != nil || !present {
		t.Fatal("audit rollback lost challenge", err)
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER reject_status_audit ON auth.account_status_audit; DROP FUNCTION auth.reject_status_audit()`); err != nil {
		t.Fatal(err)
	}
	// An invalid actor must fail the same atomic boundary, not leave a blocked account.
	_, err = f.status.Change(ctx, accountdomain.StatusChange{UserID: f.user, ActorID: "00000000-0000-0000-0000-000000000000", Status: accountdomain.StatusBlocked, ExpectedVersion: 1})
	if err == nil {
		t.Fatal("unknown audit actor accepted")
	}
	if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
		t.Fatal("actor failure did not roll back", err)
	}
}

type loginTestHasher struct{ afterCompare func() error }

func (loginTestHasher) NeedsRehash(string) bool { return false }

type loginTestLimit struct{}

func (loginTestLimit) Allow(context.Context, string, string) error { return nil }

func (h loginTestHasher) Compare(context.Context, string, string) error {
	if h.afterCompare != nil {
		return h.afterCompare()
	}
	return nil
}

func (loginTestHasher) GenerateHash(context.Context, []byte) (string, error) {
	return "", errors.New("hash generation not expected")
}
