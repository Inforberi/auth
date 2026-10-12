package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func checkAdministratorProtection(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES ('super_admin','Super admin',true) RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES ($1,'access.roles.manage'),($1,'access.assignments.manage')`, role)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE role_id=$1`, role)
		accessExec(t, db, ctx, `DELETE FROM auth.roles WHERE id=$1`, role)
	})
	for _, action := range []string{"block", "delete"} {
		t.Run(action, func(t *testing.T) {
			f := newStatusFixture(t, db, ctx, "last-admin-"+action)
			assignAdministrator(t, db, ctx, role, f.user)
			if err := removeAdministrator(ctx, f, action, 2); !errors.Is(err, accountdomain.ErrAccountConflict) {
				t.Fatal("stale version lost precedence", err)
			}
			if err := removeAdministrator(ctx, f, action, 1); !errors.Is(err, accountdomain.ErrLastAdministrator) {
				t.Fatal("last administrator removed", err)
			}
			assertAdministratorIntact(t, db, ctx, f)
			backup := newStatusFixture(t, db, ctx, "last-admin-backup-"+action)
			assignAdministrator(t, db, ctx, role, backup.user)
			for _, state := range []string{"blocked", "pending", "deleted"} {
				query := `UPDATE auth.users SET status=$2,deleted_at=NULL WHERE id=$1`
				status := state
				if state == "deleted" {
					query, status = `UPDATE auth.users SET status=$2,deleted_at=clock_timestamp() WHERE id=$1`, "blocked"
				}
				accessExec(t, db, ctx, query, backup.user, status)
				if err := removeAdministrator(ctx, f, action, 1); !errors.Is(err, accountdomain.ErrLastAdministrator) {
					t.Fatal("inactive backup counted", state, err)
				}
			}
			accessExec(t, db, ctx, `UPDATE auth.users SET status='active',deleted_at=NULL WHERE id=$1`, backup.user)
			if err := removeAdministrator(ctx, f, action, 1); err != nil {
				t.Fatal("active backup not counted", err)
			}
			if err := removeAdministrator(ctx, backup, action, 1); !errors.Is(err, accountdomain.ErrLastAdministrator) {
				t.Fatal("remaining administrator removed", err)
			}
			assertAdministratorIntact(t, db, ctx, backup)
		})
	}
	for _, actions := range [][2]string{{"block", "block"}, {"block", "delete"}, {"delete", "delete"}} {
		t.Run(actions[0]+"-"+actions[1]+"-race", func(t *testing.T) {
			first := newStatusFixture(t, db, ctx, "admin-race-first-"+actions[0]+actions[1])
			second := newStatusFixture(t, db, ctx, "admin-race-second-"+actions[0]+actions[1])
			assignAdministrator(t, db, ctx, role, first.user)
			assignAdministrator(t, db, ctx, role, second.user)
			a, b := protectionPair(func() error { return removeAdministrator(ctx, first, actions[0], 1) },
				func() error { return removeAdministrator(ctx, second, actions[1], 1) })
			firstWon := a == nil && errors.Is(b, accountdomain.ErrLastAdministrator)
			secondWon := b == nil && errors.Is(a, accountdomain.ErrLastAdministrator)
			if !firstWon && !secondWon {
				t.Fatal("expected one winner and one protected administrator", a, b)
			}
			if a == nil {
				assertAdministratorIntact(t, db, ctx, second)
			} else {
				assertAdministratorIntact(t, db, ctx, first)
			}
		})
	}
	t.Run("bounded-lock-wait", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "admin-lock-wait")
		assignAdministrator(t, db, ctx, role, f.user)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := tx.Rollback(ctx); err != nil {
				t.Error(err)
			}
		})
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		if err := removeAdministrator(bounded, f, "block", 1); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("lock wait ignored deadline", err)
		}
		assertAdministratorIntact(t, db, ctx, f)
	})
	t.Run("recovery", func(t *testing.T) { checkAdministratorRecovery(t, db, ctx, role) })
}

func assignAdministrator(t *testing.T, db *pgxpool.Pool, ctx context.Context, role string, user accountdomain.UserID) {
	t.Helper()
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES ($1,$2)`, user, role)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`, user, role)
	})
}

func removeAdministrator(ctx context.Context, f statusFixture, action string, version accountdomain.AuthVersion) error {
	if action == "delete" {
		_, err := deleteFixture(ctx, f, version)
		return err
	}
	_, err := f.change(ctx, accountdomain.StatusBlocked, version)
	return err
}

func assertAdministratorIntact(t *testing.T, db *pgxpool.Pool, ctx context.Context, f statusFixture) {
	t.Helper()
	if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
		t.Fatal("failed removal revoked session", err)
	}
	var intact bool
	if err := db.QueryRow(ctx, `SELECT status='active' AND deleted_at IS NULL AND auth_version=1
		AND NOT EXISTS(SELECT 1 FROM auth.account_status_audit WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_deletion_audit WHERE user_id=$1)
		FROM auth.users WHERE id=$1`, f.user).Scan(&intact); err != nil || !intact {
		t.Fatal("failed removal changed account or audit", intact, err)
	}
}
