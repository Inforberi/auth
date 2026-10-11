package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	telegramdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func identityManagementFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) (statusFixture, *accountservice.IdentityManagement) {
	t.Helper()
	f := newStatusFixture(t, db, ctx, "identity-"+name)
	if _, err := db.Exec(ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1;
		`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	return f, accountservice.NewIdentityManagement(f.accounts, 5*time.Minute)
}

func checkIdentityManagement(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("link-unlink", func(t *testing.T) {
		f, management := identityManagementFixture(t, db, ctx, "basic")
		key := accountdomain.IdentityKey{Issuer: telegramdomain.Issuer, Subject: "link-basic"}
		if err := management.RequireFresh(ctx, f.user, f.params.TokenHash); err != nil {
			t.Fatal(err)
		}
		if err := management.Link(ctx, f.user, f.params.TokenHash, key); err != nil {
			t.Fatal(err)
		}
		if err := management.Link(ctx, f.user, f.params.TokenHash, key); err != nil {
			t.Fatal("same-owner retry", err)
		}
		other := key
		other.Subject = "different-subject"
		if err := management.Link(ctx, f.user, f.params.TokenHash, other); !errors.Is(err, accountdomain.ErrIdentityConflict) {
			t.Fatal("multiple identities of one provider", err)
		}
		resolved, err := accountservice.NewIdentityResolution(f.accounts).Resolve(ctx, key, false)
		if err != nil || resolved.ID != f.user {
			t.Fatal("link created another user", resolved, err)
		}
		var audits int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.identity_audit WHERE user_id=$1 AND event='identity_linked'`, f.user).Scan(&audits); err != nil || audits != 1 {
			t.Fatal("duplicate link audit", audits, err)
		}
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
			t.Fatal("link revoked current session", err)
		}
		if err := management.Unlink(ctx, f.actor, f.params.TokenHash, key.Issuer); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
			t.Fatal("foreign owner", err)
		}
		if err := management.Unlink(ctx, f.user, f.params.TokenHash, key.Issuer); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("unlink preserved session", err)
		}
		if _, err := accountservice.NewIdentityResolution(f.accounts).Resolve(ctx, key, false); !errors.Is(err, accountdomain.ErrIdentityNotFound) {
			t.Fatal("unlink preserved method", err)
		}
		var version int64
		if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, f.user).Scan(&version); err != nil || version != 2 {
			t.Fatal(version, err)
		}
	})
	t.Run("ownership-race", func(t *testing.T) {
		a, ma := identityManagementFixture(t, db, ctx, "race-a")
		b, mb := identityManagementFixture(t, db, ctx, "race-b")
		key := accountdomain.IdentityKey{Issuer: telegramdomain.Issuer, Subject: "race-owned"}
		var successes atomic.Int64
		var wg sync.WaitGroup
		for _, f := range []struct {
			fixture statusFixture
			manager *accountservice.IdentityManagement
		}{{a, ma}, {b, mb}} {
			wg.Go(func() {
				err := f.manager.Link(ctx, f.fixture.user, f.fixture.params.TokenHash, key)
				if err == nil {
					successes.Add(1)
				} else if !errors.Is(err, accountdomain.ErrIdentityConflict) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatal("identity stolen/split", successes.Load())
		}
	})
	t.Run("fresh-guards", func(t *testing.T) {
		for i, query := range []string{
			`UPDATE auth.sessions SET password_verified_at=NULL WHERE user_id=$1`,
			`UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE user_id=$1`,
			`UPDATE auth.sessions SET password_verified_at=clock_timestamp()+interval '1 minute' WHERE user_id=$1`,
			`UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`,
			`UPDATE auth.sessions SET expires_at=clock_timestamp() WHERE user_id=$1`,
			`UPDATE auth.sessions SET created_at=statement_timestamp()-interval '2 hours',
				expires_at=statement_timestamp()-interval '1 second',absolute_expires_at=statement_timestamp()-interval '1 second' WHERE user_id=$1`,
			`UPDATE auth.sessions SET token_hash=encode(digest($1::text||'-rotated','sha256'),'hex') WHERE user_id=$1`,
			`UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
			`UPDATE auth.users SET status='blocked' WHERE id=$1`,
			`UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`,
		} {
			f, management := identityManagementFixture(t, db, ctx, fmt.Sprintf("guard-%d", i))
			key := accountdomain.IdentityKey{Issuer: telegramdomain.Issuer, Subject: fmt.Sprintf("guard-%d", i)}
			if err := management.Link(ctx, f.user, f.params.TokenHash, key); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, query, f.user); err != nil {
				t.Fatal(err)
			}
			if err := management.RequireFresh(ctx, f.user, f.params.TokenHash); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
				t.Fatal("stale start", i, err)
			}
			if err := management.Link(ctx, f.user, f.params.TokenHash, key); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
				t.Fatal("stale callback", i, err)
			}
			if err := management.Unlink(ctx, f.user, f.params.TokenHash, key.Issuer); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
				t.Fatal("stale unlink", i, err)
			}
		}
	})
	t.Run("last-method", func(t *testing.T) {
		for i, query := range []string{
			`UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`,
			`DELETE FROM auth.password_credentials WHERE user_id=$1`,
		} {
			f, management := identityManagementFixture(t, db, ctx, fmt.Sprintf("last-%d", i))
			key := accountdomain.IdentityKey{Issuer: telegramdomain.Issuer, Subject: fmt.Sprintf("last-%d", i)}
			if err := management.Link(ctx, f.user, f.params.TokenHash, key); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, query, f.user); err != nil {
				t.Fatal(err)
			}
			if err := management.RequireFresh(ctx, f.user, f.params.TokenHash); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
				t.Fatal("unverified or missing password authorized link start", i, err)
			}
			if err := management.Link(ctx, f.user, f.params.TokenHash, key); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
				t.Fatal("unverified or missing password authorized callback", i, err)
			}
			if err := management.Unlink(ctx, f.user, f.params.TokenHash, key.Issuer); !errors.Is(err, accountdomain.ErrLastLoginMethod) {
				t.Fatal("last usable method removed", i, err)
			}
		}
	})
	t.Run("unlink-race", func(t *testing.T) {
		f, management := identityManagementFixture(t, db, ctx, "unlink-race")
		key := accountdomain.IdentityKey{Issuer: telegramdomain.Issuer, Subject: "unlink-race"}
		if err := management.Link(ctx, f.user, f.params.TokenHash, key); err != nil {
			t.Fatal(err)
		}
		var successes atomic.Int64
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				err := management.Unlink(ctx, f.user, f.params.TokenHash, key.Issuer)
				if err == nil {
					successes.Add(1)
				} else if !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatal("unlink not serialized", successes.Load())
		}
	})
	t.Run("audit-rollback", func(t *testing.T) {
		f, management := identityManagementFixture(t, db, ctx, "rollback")
		key := accountdomain.IdentityKey{Issuer: telegramdomain.Issuer, Subject: "audit-rollback"}
		if _, err := db.Exec(ctx, `ALTER TABLE auth.identity_audit ADD CONSTRAINT reject_management_audit CHECK (event='identity_created') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		if err := management.Link(ctx, f.user, f.params.TokenHash, key); err == nil {
			t.Fatal("link audit failure ignored")
		}
		var linked bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.linked_identities WHERE user_id=$1)`, f.user).Scan(&linked); err != nil || linked {
			t.Fatal("link not rolled back", linked, err)
		}
		if _, err := db.Exec(ctx, `ALTER TABLE auth.identity_audit DROP CONSTRAINT reject_management_audit`); err != nil {
			t.Fatal(err)
		}
		if err := management.Link(ctx, f.user, f.params.TokenHash, key); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `ALTER TABLE auth.identity_audit ADD CONSTRAINT reject_management_audit CHECK (event<>'identity_unlinked') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		if err := management.Unlink(ctx, f.user, f.params.TokenHash, key.Issuer); err == nil {
			t.Fatal("unlink audit failure ignored")
		}
		if err := management.RequireFresh(ctx, f.user, f.params.TokenHash); err != nil {
			t.Fatal("rollback revoked session", err)
		}
		if _, err := accountservice.NewIdentityResolution(f.accounts).Resolve(ctx, key, false); err != nil {
			t.Fatal("rollback removed link", err)
		}
		if _, err := db.Exec(ctx, `ALTER TABLE auth.identity_audit DROP CONSTRAINT reject_management_audit`); err != nil {
			t.Fatal(err)
		}
	})
}
