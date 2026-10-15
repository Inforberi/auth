package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func checkTemporaryFailures(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("expiry-and-bounded-cleanup", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "expiry")
		created := f.create(t, ctx)
		if _, err := db.Exec(ctx, `UPDATE auth.temporary_password_credentials SET expires_at=clock_timestamp()+interval '30 seconds' WHERE user_id=$1`, created.UserID); err != nil {
			t.Fatal(err)
		}
		setup := f.login(t, ctx, created.Password)
		if setup.ExpiresAt.After(time.Now().Add(31 * time.Second)) {
			t.Fatal("setup extends temporary credential TTL")
		}
		if _, err := db.Exec(ctx, `UPDATE auth.temporary_password_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1`, created.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.Login(ctx, f.input.Email, created.Password, "ip"); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("expired temporary password accepted", err)
		}
		if err := f.service.Complete(ctx, setup.Token, "PermanentExamplePass123", "PermanentExamplePass123", "ip"); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("expired credential's token accepted", err)
		}
		cfg := accountservice.RetentionConfig{SessionDays: 30, SecurityAuditDays: 180, EmailReservationDays: 30, BatchSize: 100}
		if _, err := f.accounts.PurgeRetention(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		var temporary int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.temporary_password_credentials WHERE user_id=$1`, created.UserID).Scan(&temporary); err != nil || temporary != 0 {
			t.Fatal("expired hash not cleaned", err)
		}
		allowTemporaryReissue(t, db, ctx, created.UserID)
		if _, err := f.service.Reissue(ctx, passwordservice.TemporaryReissueInput{Actor: f.input.Actor, UserID: created.UserID, IdempotencyKey: temporaryRequestKey(t, db, ctx)}); err != nil {
			t.Fatal("cleanup lost durable reissue state", err)
		}
	})
	t.Run("block-and-delete", func(t *testing.T) {
		for _, deleting := range []bool{false, true} {
			name := "block"
			if deleting {
				name = "delete"
			}
			f := newTemporaryFixture(t, db, ctx, name)
			created := f.create(t, ctx)
			setup := f.login(t, ctx, created.Password)
			var err error
			if deleting {
				_, err = f.accounts.DeleteAccount(ctx, accountdomain.AccountDeletion{UserID: created.UserID, ActorID: f.input.Actor.UserID, ExpectedVersion: 1})
			} else {
				_, err = f.accounts.ChangeStatus(ctx, accountdomain.StatusChange{UserID: created.UserID, ActorID: f.input.Actor.UserID, Status: accountdomain.StatusBlocked, ExpectedVersion: 1})
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.Login(ctx, f.input.Email, created.Password, "ip"); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
				t.Fatal("blocked/deleted secret valid", err)
			}
			if err := f.service.Complete(ctx, setup.Token, "PermanentExamplePass123", "PermanentExamplePass123", "ip"); !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
				t.Fatal("blocked/deleted authority valid", err)
			}
			if _, err := f.accounts.ChangeStatus(ctx, accountdomain.StatusChange{UserID: created.UserID, ActorID: f.input.Actor.UserID, Status: accountdomain.StatusActive, ExpectedVersion: 2}); err == nil {
				t.Fatal("unblock bypassed password setup")
			}
		}
	})
	t.Run("audit-rollback", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "audit")
		if _, err := db.Exec(ctx, `ALTER TABLE auth.password_audit ADD CONSTRAINT fixture_temporary_issue_fail CHECK(event<>'temporary_password_issued') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		_, issueErr := f.service.Provision(ctx, f.input)
		if _, err := db.Exec(ctx, `ALTER TABLE auth.password_audit DROP CONSTRAINT fixture_temporary_issue_fail`); err != nil {
			t.Fatal(err)
		}
		if issueErr == nil {
			t.Fatal("audit failure created temporary account")
		}
		var users int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.user_emails WHERE email=$1`, f.input.Email).Scan(&users); err != nil || users != 0 {
			t.Fatal("creation rollback left user/contact", err, users)
		}
		created := f.create(t, ctx)
		setup := f.login(t, ctx, created.Password)
		if _, err := db.Exec(ctx, `ALTER TABLE auth.password_audit ADD CONSTRAINT fixture_temporary_complete_fail CHECK(event<>'temporary_password_completed') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		completeErr := f.service.Complete(ctx, setup.Token, "PermanentExamplePass123", "PermanentExamplePass123", "ip")
		if _, err := db.Exec(ctx, `ALTER TABLE auth.password_audit DROP CONSTRAINT fixture_temporary_complete_fail`); err != nil {
			t.Fatal(err)
		}
		if completeErr == nil {
			t.Fatal("audit failure activated account")
		}
		assertTemporaryState(t, db, ctx, created.UserID, true)
		if err := f.service.Complete(ctx, setup.Token, "PermanentExamplePass123", "PermanentExamplePass123", "ip"); err != nil {
			t.Fatal("rollback consumed token", err)
		}
	})
	t.Run("reissue-completion-race", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "race")
		created := f.create(t, ctx)
		setup := f.login(t, ctx, created.Password)
		allowTemporaryReissue(t, db, ctx, created.UserID)
		input := passwordservice.TemporaryReissueInput{Actor: f.input.Actor, UserID: created.UserID, IdempotencyKey: temporaryRequestKey(t, db, ctx)}
		var reissueErr, completeErr error
		var wg sync.WaitGroup
		wg.Go(func() { _, reissueErr = f.service.Reissue(ctx, input) })
		wg.Go(func() {
			completeErr = f.service.Complete(ctx, setup.Token, "PermanentExamplePass123", "PermanentExamplePass123", "ip")
		})
		wg.Wait()
		if completeErr == nil {
			if !errors.Is(reissueErr, passworddomain.ErrInvalidTemporaryPassword) {
				t.Fatal("reissued activated account", reissueErr)
			}
		} else if reissueErr != nil || !errors.Is(completeErr, passworddomain.ErrInvalidTemporaryPassword) {
			t.Fatal("unexpected race result", completeErr, reissueErr)
		}
	})
}
