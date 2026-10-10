package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func checkInvitationDelivery(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	f := newInvitationFixture(t, db, ctx, "delivery")
	user, digest, _ := f.create(t, db, ctx)
	// Isolate this candidate; other scenario fixtures may contain live invitations.
	if _, err := db.Exec(ctx, `UPDATE auth.invitation_outbox SET available_at=clock_timestamp()+interval '1 hour' WHERE digest<>$1`, digest); err != nil {
		t.Fatal(err)
	}
	job, err := f.accounts.ClaimDelivery(ctx)
	if err != nil || job == nil || !job.Invitation || job.Attempts != 1 {
		t.Fatal("claim", job, err)
	}
	if err := f.accounts.FinishDelivery(ctx, *job, false); err != nil {
		t.Fatal(err)
	}
	var delayed bool
	if err := db.QueryRow(ctx, `SELECT lease IS NULL AND lease_until IS NULL AND available_at>clock_timestamp() FROM auth.invitation_outbox WHERE digest=$1`, digest).Scan(&delayed); err != nil || !delayed {
		t.Fatal("retry not paced", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.invitation_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE digest=$1`, digest); err != nil {
		t.Fatal(err)
	}
	second, err := f.accounts.ClaimDelivery(ctx)
	if err != nil || second == nil || second.Attempts != 2 {
		t.Fatal("second claim", second, err)
	}
	if err := f.accounts.FinishDelivery(ctx, *job, true); err != nil {
		t.Fatal(err)
	}
	var retained bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.invitation_outbox WHERE digest=$1)`, digest).Scan(&retained); err != nil || !retained {
		t.Fatal("stale lease removed job", err)
	}
	if err := f.accounts.FinishDelivery(ctx, *second, true); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.CheckInvitation(ctx, digest); err != nil {
		t.Fatal("delivery consumed token", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.account_invitations SET expires_at=clock_timestamp()-interval '1 second' WHERE digest=$1`, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := f.accounts.PurgeRetention(ctx, accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 100, Interval: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.CheckInvitation(ctx, digest); !errors.Is(err, accountdomain.ErrInvalidInvitation) {
		t.Fatal("expired invitation retained", err)
	}
	assertInvitationState(t, db, ctx, user, "pending", false, false)
}

func checkProvisionRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	f := newInvitationFixture(t, db, ctx, "provision-rollback")
	if _, err := db.Exec(ctx, `ALTER TABLE auth.invitation_audit ADD CONSTRAINT fixture_provision_audit_fail CHECK(action<>'provisioned') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err := db.Exec(ctx, `ALTER TABLE auth.invitation_audit DROP CONSTRAINT fixture_provision_audit_fail`)
		if err != nil {
			t.Error(err)
		}
	}()
	if _, err := f.provision.Provision(ctx, f.input); err == nil {
		t.Fatal("failed audit allowed provisioning")
	}
	var intact bool
	if err := db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE actor_id=$1 AND request_key=$2)
		AND NOT EXISTS(SELECT 1 FROM auth.user_emails WHERE email=$3)`, f.input.ActorID, f.input.IdempotencyKey, f.input.Email).Scan(&intact); err != nil || !intact {
		t.Fatal("partial creation", err)
	}
}
