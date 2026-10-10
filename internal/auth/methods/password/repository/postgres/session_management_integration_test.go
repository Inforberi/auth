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
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func checkSessionManagement(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	users := New(db)
	owner, err := users.CreateUser(ctx, "sessions@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := users.CreateUser(ctx, "foreign-sessions@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	ledger := sessionpostgres.New(db)
	issue := func(user accountdomain.UserID, hash string) *sessiondomain.Session {
		t.Helper()
		p := sessionservice.CreateSessionParams{
			UserID: user, AuthVersion: 1, TokenHash: hash,
			CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), AbsoluteExpiresAt: time.Now().UTC().Add(2 * time.Hour),
		}
		if err := ledger.CreateSession(ctx, p); err != nil {
			t.Fatal(err)
		}
		row, err := ledger.FindSession(ctx, hash)
		if err != nil {
			t.Fatal(err)
		}
		if sessiondomain.ValidateID(row.ID) != nil {
			t.Fatal("public UUID missing", err)
		}
		return row
	}
	callerHash := strings.Repeat("1", 64)
	caller := issue(owner, callerHash)
	otherHash := strings.Repeat("2", 64)
	other := issue(owner, otherHash)
	foreignHash := strings.Repeat("3", 64)
	foreignSession := issue(foreign, foreignHash)
	if err := ledger.RevokeOwnSession(ctx, owner, callerHash, foreignSession.ID); !errors.Is(err, sessiondomain.ErrOwnedSessionNotFound) {
		t.Fatal("foreign session disclosed/revoked", err)
	}
	if err := ledger.RevokeOwnSession(ctx, owner, callerHash, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, sessiondomain.ErrOwnedSessionNotFound) {
		t.Fatal("unknown ID contract", err)
	}
	if _, err := ledger.ListOwnSessions(ctx, owner, callerHash, foreignSession.ID, 51); !errors.Is(err, sessiondomain.ErrInvalidSessionID) {
		t.Fatal("foreign cursor accepted", err)
	}
	if err := ledger.RevokeOwnSessions(ctx, owner, foreignHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("foreign caller authorized", err)
	}
	for i := range 51 {
		issue(owner, fmt.Sprintf("%064x", i+100))
	}
	management := sessionservice.NewManagement(ledger)
	page, err := management.List(ctx, owner, callerHash, "")
	if err != nil || len(page.Sessions) != 50 || page.NextCursor == "" {
		t.Fatal("first page", err)
	}
	seen := map[string]bool{}
	for _, session := range page.Sessions {
		if session.UserID != owner || session.ID == callerHash || session.ID == foreignSession.ID {
			t.Fatal("session isolation")
		}
		seen[session.ID] = true
	}
	next, err := management.List(ctx, owner, callerHash, page.NextCursor)
	if err != nil || len(next.Sessions) != 3 || next.NextCursor != "" {
		t.Fatal("second page", err)
	}
	for _, session := range next.Sessions {
		if seen[session.ID] {
			t.Fatal("duplicate cursor result")
		}
	}
	checkRevokeAuditRollback(t, db, ctx, ledger, owner, callerHash, other)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() { errs[i] = ledger.RevokeOwnSession(ctx, owner, callerHash, other.ID) })
	}
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, sessiondomain.ErrOwnedSessionNotFound) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("revoke replay committed")
	}
	if _, err := ledger.FindSession(ctx, otherHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("revoked session survived", err)
	}
	var issueErr, logoutErr error
	racingHash := strings.Repeat("4", 64)
	wg.Go(func() {
		issueErr = ledger.CreateSession(ctx, sessionservice.CreateSessionParams{
			UserID: owner, AuthVersion: 1, TokenHash: racingHash,
			CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), AbsoluteExpiresAt: time.Now().UTC().Add(2 * time.Hour),
		})
	})
	wg.Go(func() { logoutErr = ledger.RevokeOwnSessions(ctx, owner, callerHash) })
	wg.Wait()
	if logoutErr != nil || issueErr != nil && !errors.Is(issueErr, sessiondomain.ErrSessionNotFound) {
		t.Fatal("concurrent logout-all/issuance", logoutErr, issueErr)
	}
	if _, err := ledger.FindSession(ctx, racingHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("racing issuance survived logout-all", err)
	}
	if _, err := ledger.FindSession(ctx, callerHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("logout-all kept caller", err)
	}
	if err := ledger.RevokeOwnSession(ctx, owner, callerHash, caller.ID); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("revoked caller authorized", err)
	}
	if _, err := ledger.FindSession(ctx, foreignHash); err != nil {
		t.Fatal("logout-all revoked foreign session", err)
	}
	if err := ledger.RevokeOwnSession(ctx, foreign, foreignHash, foreignSession.ID); err != nil {
		t.Fatal("current session revoke", err)
	}
	if _, err := ledger.FindSession(ctx, foreignHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("current session survived logout", err)
	}
	var version int64
	if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, owner).Scan(&version); err != nil || version != 2 {
		t.Fatal("logout-all version", version, err)
	}
	if err := ledger.CreateSession(ctx, sessionservice.CreateSessionParams{UserID: owner, AuthVersion: 1}); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("stale issuance accepted", err)
	}
	foreignHash = strings.Repeat("5", 64)
	issue(foreign, foreignHash)
	if _, err := db.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.ListOwnSessions(ctx, foreign, foreignHash, "", 51); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("blocked caller authorized", err)
	}
}

func checkRevokeAuditRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, ledger *sessionpostgres.Repository, user accountdomain.UserID, callerHash string, target *sessiondomain.Session) {
	t.Helper()
	if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_session_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
  CREATE TRIGGER reject_session_audit BEFORE INSERT ON auth.password_audit FOR EACH ROW WHEN (NEW.event='sessions_revoked') EXECUTE FUNCTION auth.reject_session_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RevokeOwnSession(ctx, user, callerHash, target.ID); err == nil {
		t.Fatal("revoke committed without audit")
	}
	if err := ledger.RevokeOwnSessions(ctx, user, callerHash); err == nil {
		t.Fatal("logout-all committed without audit")
	}
	var revoked bool
	var version int64
	if err := db.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth.sessions WHERE id=$1`, target.ID).Scan(&revoked); err != nil || revoked {
		t.Fatal("audit rollback revoked target", err)
	}
	if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, user).Scan(&version); err != nil || version != 1 {
		t.Fatal("audit rollback changed auth version", err)
	}
	if _, err := ledger.FindSession(ctx, callerHash); err != nil {
		t.Fatal("audit rollback revoked caller", err)
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER reject_session_audit ON auth.password_audit; DROP FUNCTION auth.reject_session_audit()`); err != nil {
		t.Fatal(err)
	}
}
