package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func checkRecovery(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	repo := New(db)
	user, err := repo.CreateUser(ctx, "reset@example.com", "old-hash")
	if err != nil {
		t.Fatal(err)
	}
	ledger := sessionpostgres.New(db)
	params := sessionservice.CreateSessionParams{UserID: user, AuthVersion: 1, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), AbsoluteExpiresAt: time.Now().UTC().Add(2 * time.Hour), TokenHash: strings.Repeat("a", 64)}
	if _, err := ledger.CreateSession(ctx, params); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.FindSession(ctx, params.TokenHash); err != nil {
		t.Fatal(err)
	}
	challenge := domain.ResetChallenge{Digest: strings.Repeat("b", 64), Payload: make([]byte, 32), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := repo.IssueReset(ctx, "unknown@example.com", challenge); err != nil {
		t.Fatal(err)
	}
	if err := repo.IssueReset(ctx, "reset@example.com", challenge); err != nil {
		t.Fatal(err)
	}
	job, err := repo.ClaimResetDelivery(ctx)
	if err != nil || job == nil {
		t.Fatal("missing outbox", err)
	}
	if another, err := repo.ClaimResetDelivery(ctx); err != nil || another != nil {
		t.Fatal("duplicate lease", err)
	}
	if err := repo.FinishResetDelivery(ctx, *job, false); err != nil {
		t.Fatal(err)
	}
	replacement := challenge
	replacement.Digest = strings.Repeat("c", 64)
	if err := repo.IssueReset(ctx, "reset@example.com", replacement); err != nil {
		t.Fatal(err)
	}
	var actual string
	if err := db.QueryRow(ctx, `SELECT digest FROM auth.password_resets WHERE user_id=$1`, user).Scan(&actual); err != nil || actual != challenge.Digest {
		t.Fatal("cooldown bypass", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.password_resets SET created_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if err := repo.IssueReset(ctx, "reset@example.com", replacement); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(repo.ConsumeReset(ctx, challenge.Digest, "new-hash"), domain.ErrInvalidReset) {
		t.Fatal("old reset accepted")
	}
	checkResetAuditFailure(t, db, ctx, repo, replacement, ledger, params)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- repo.ConsumeReset(ctx, replacement.Digest, "new-hash") })
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, domain.ErrInvalidReset) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatal("reset not single-use")
	}
	if !errors.Is(repo.ConsumeReset(ctx, replacement.Digest, "again"), domain.ErrInvalidReset) {
		t.Fatal("replay accepted")
	}
	if _, err := ledger.FindSession(ctx, params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("old session accepted", err)
	}
	if _, err := ledger.CreateSession(ctx, params); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("old-password issuance accepted", err)
	}
	stale := &sessiondomain.Session{UserID: user, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if _, err := ledger.RefreshSession(ctx, params.TokenHash, stale, stale.ExpiresAt); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("revoked session resurrected", err)
	}
	credential, err := repo.FindByEmail(ctx, "reset@example.com")
	if err != nil || credential.PasswordHash != "new-hash" || credential.AuthVersion != 2 {
		t.Fatal("reset not committed", err)
	}
	params.AuthVersion = 2
	params.TokenHash = strings.Repeat("d", 64)
	if _, err := ledger.CreateSession(ctx, params); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.FindSession(ctx, params.TokenHash); err != nil {
		t.Fatal(err)
	}
	if err := repo.ChangePassword(ctx, user, params.TokenHash, "old-hash", "changed"); !errors.Is(err, domain.ErrInvalidEmailOrPassword) {
		t.Fatal("stale credential snapshot accepted", err)
	}
	if err := repo.ChangePassword(ctx, user, params.TokenHash, "new-hash", "changed-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.FindSession(ctx, params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("change-password session survived", err)
	}
	checkResetExpiry(t, db, ctx, repo, user, replacement)
}

func checkResetAuditFailure(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo *PasswordRepo, c domain.ResetChallenge, ledger *sessionpostgres.Repository, p sessionservice.CreateSessionParams) {
	t.Helper()
	if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_reset_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
		CREATE TRIGGER reject_reset_audit BEFORE INSERT ON auth.password_audit FOR EACH ROW WHEN (NEW.event='password_reset') EXECUTE FUNCTION auth.reject_reset_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := repo.ConsumeReset(ctx, c.Digest, "new-hash"); err == nil {
		t.Fatal("audit failure committed")
	}
	credential, err := repo.FindByEmail(ctx, "reset@example.com")
	if err != nil || credential.PasswordHash != "old-hash" || credential.AuthVersion != 1 {
		t.Fatal("audit failure changed password", err)
	}
	if _, err := ledger.FindSession(ctx, p.TokenHash); err != nil {
		t.Fatal("audit failure revoked session", err)
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER reject_reset_audit ON auth.password_audit; DROP FUNCTION auth.reject_reset_audit()`); err != nil {
		t.Fatal(err)
	}
}

func checkResetExpiry(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo *PasswordRepo, user accountdomain.UserID, c domain.ResetChallenge) {
	t.Helper()
	if err := repo.IssueReset(ctx, "reset@example.com", c); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.password_resets SET created_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp() WHERE user_id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(repo.ConsumeReset(ctx, c.Digest, "expired"), domain.ErrInvalidReset) {
		t.Fatal("expired reset accepted")
	}
	if job, err := repo.ClaimResetDelivery(ctx); err != nil || job != nil {
		t.Fatal("expired mail claimed", err)
	}
	if err := repo.IssueReset(ctx, "reset@example.com", c); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(repo.ConsumeReset(ctx, c.Digest, "blocked"), domain.ErrInvalidReset) {
		t.Fatal("blocked reset accepted")
	}
}
