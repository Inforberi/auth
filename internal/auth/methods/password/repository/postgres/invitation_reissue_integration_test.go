package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func checkInvitationReissue(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("replacement-replay-cooldown", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "reissue")
		user, oldDigest, _ := f.create(t, db, ctx)
		input := reissueInput(t, db, ctx, f, user)
		if _, err := f.provision.ReissueInvitation(ctx, input); !errors.Is(err, accountdomain.ErrInvitationCooldown) {
			t.Fatal("initial invitation ignored by cooldown", err)
		}
		allowInvitationReissue(t, db, ctx, user)
		var wg sync.WaitGroup
		results := make(chan *accountservice.ProvisionResult, 16)
		errs := make(chan error, 16)
		for range 16 {
			wg.Go(func() {
				result, err := f.provision.ReissueInvitation(ctx, input)
				results <- result
				errs <- err
			})
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		created := 0
		for result := range results {
			if result.UserID != user {
				t.Fatal("different UUID")
			}
			if !result.Reused {
				created++
			}
		}
		if created != 1 {
			t.Fatal("duplicate replacement", created)
		}
		if err := f.accounts.CheckInvitation(ctx, oldDigest); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
			t.Fatal("old token still accepted", err)
		}
		var digest string
		if err := db.QueryRow(ctx, `SELECT digest FROM auth.account_invitations WHERE user_id=$1`, user).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.CheckInvitation(ctx, digest); err != nil {
			t.Fatal(err)
		}
		assertReissueCounts(t, db, ctx, user, 1)
		next := reissueInput(t, db, ctx, f, user)
		if _, err := f.provision.ReissueInvitation(ctx, next); !errors.Is(err, accountdomain.ErrInvitationCooldown) {
			t.Fatal("repeat send ignored cooldown", err)
		}
		other := newInvitationFixture(t, db, ctx, "reissue-conflict")
		otherUser, _, _ := other.create(t, db, ctx)
		input.UserID = otherUser
		if _, err := f.provision.ReissueInvitation(ctx, input); !errors.Is(err, accountdomain.ErrProvisionConflict) {
			t.Fatal("idempotency key reused for another target", err)
		}
	})
	t.Run("audit-rollback-and-expired-token", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "reissue-rollback")
		user, digest, _ := f.create(t, db, ctx)
		allowInvitationReissue(t, db, ctx, user)
		input := reissueInput(t, db, ctx, f, user)
		if _, err := db.Exec(ctx, `ALTER TABLE auth.invitation_audit ADD CONSTRAINT fixture_reissue_fail CHECK(action<>'reissued') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		_, reissueErr := f.provision.ReissueInvitation(ctx, input)
		if _, err := db.Exec(ctx, `ALTER TABLE auth.invitation_audit DROP CONSTRAINT fixture_reissue_fail`); err != nil {
			t.Fatal(err)
		}
		if reissueErr == nil {
			t.Fatal("audit failure accepted")
		}
		if err := f.accounts.CheckInvitation(ctx, digest); err != nil {
			t.Fatal("rollback invalidated old token", err)
		}
		assertReissueCounts(t, db, ctx, user, 0)
		if _, err := db.Exec(ctx, `DELETE FROM auth.account_invitations WHERE user_id=$1`, user); err != nil {
			t.Fatal(err)
		}
		if _, err := f.provision.ReissueInvitation(ctx, input); err != nil {
			t.Fatal("cannot replace cleaned token", err)
		}
		assertReissueCounts(t, db, ctx, user, 1)
	})
	t.Run("pending-only", func(t *testing.T) {
		for _, status := range []string{"active", "blocked"} {
			f := newInvitationFixture(t, db, ctx, "reissue-"+status)
			user, _, _ := f.create(t, db, ctx)
			allowInvitationReissue(t, db, ctx, user)
			if _, err := db.Exec(ctx, `UPDATE auth.users SET status=$2 WHERE id=$1`, user, status); err != nil {
				t.Fatal(err)
			}
			if _, err := f.provision.ReissueInvitation(ctx, reissueInput(t, db, ctx, f, user)); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
				t.Fatal("non-pending target accepted", status, err)
			}
		}
	})
	t.Run("activation-race", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "reissue-activation-race")
		user, digest, _ := f.create(t, db, ctx)
		allowInvitationReissue(t, db, ctx, user)
		input := reissueInput(t, db, ctx, f, user)
		var activationErr, reissueErr error
		var wg sync.WaitGroup
		wg.Go(func() { activationErr = f.accounts.ActivateInvitation(ctx, digest, "activated-hash") })
		wg.Go(func() { _, reissueErr = f.provision.ReissueInvitation(ctx, input) })
		wg.Wait()
		if activationErr == nil {
			if !errors.Is(reissueErr, accountdomain.ErrInvalidInvitation) {
				t.Fatal("reissued activated account", reissueErr)
			}
		} else if reissueErr != nil || !errors.Is(activationErr, accountdomain.ErrInvalidInvitation) {
			t.Fatal("unexpected race outcome", activationErr, reissueErr)
		}
	})
	t.Run("distinct-commands-share-cooldown", func(t *testing.T) {
		f := newInvitationFixture(t, db, ctx, "reissue-distinct")
		user, _, _ := f.create(t, db, ctx)
		allowInvitationReissue(t, db, ctx, user)
		inputs := make([]accountservice.InvitationReissueInput, 16)
		for i := range inputs {
			inputs[i] = reissueInput(t, db, ctx, f, user)
		}
		var wg sync.WaitGroup
		errs := make(chan error, len(inputs))
		for _, input := range inputs {
			wg.Go(func() { _, err := f.provision.ReissueInvitation(ctx, input); errs <- err })
		}
		wg.Wait()
		close(errs)
		accepted := 0
		for err := range errs {
			if err == nil {
				accepted++
			} else if !errors.Is(err, accountdomain.ErrInvitationCooldown) {
				t.Fatal(err)
			}
		}
		if accepted != 1 {
			t.Fatal("parallel cooldown bypass", accepted)
		}
		assertReissueCounts(t, db, ctx, user, 1)
	})
}

func reissueInput(t *testing.T, db *pgxpool.Pool, ctx context.Context, f invitationFixture, user accountdomain.UserID) accountservice.InvitationReissueInput {
	t.Helper()
	var key string
	if err := db.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&key); err != nil {
		t.Fatal(err)
	}
	return accountservice.InvitationReissueInput{ActorID: f.input.ActorID, UserID: user, IdempotencyKey: key}
}

func allowInvitationReissue(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID) {
	t.Helper()
	if _, err := db.Exec(ctx, `UPDATE auth.account_provisions SET last_invited_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, user); err != nil {
		t.Fatal(err)
	}
}

func assertReissueCounts(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID, commands int) {
	t.Helper()
	var actualCommands, actualJobs, audits int
	if err := db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM auth.invitation_reissues WHERE user_id=$1),
		(SELECT count(*) FROM auth.invitation_outbox o JOIN auth.account_invitations i ON i.digest=o.digest WHERE i.user_id=$1),
		(SELECT count(*) FROM auth.invitation_audit WHERE user_id=$1 AND action='reissued')`, user).Scan(&actualCommands, &actualJobs, &audits); err != nil {
		t.Fatal(err)
	}
	if actualCommands != commands || actualJobs != 1 || audits != commands {
		t.Fatal("unexpected reissue state", actualCommands, actualJobs, audits)
	}
}
