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
)

func checkChangeDelivery(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	// This suite owns a dedicated disposable database; earlier scenarios left unsent fixture jobs.
	if _, err := db.Exec(ctx, `DELETE FROM auth.email_change_outbox; DELETE FROM auth.email_verification_outbox`); err != nil {
		t.Fatal(err)
	}
	f := newChangeFixture(t, db, ctx, "delivery")
	if err := f.request(ctx); err != nil {
		t.Fatal(err)
	}
	job, err := f.accounts.ClaimDelivery(ctx)
	if err != nil || job == nil || !job.EmailChange || job.Attempts != 1 {
		t.Fatal("claim", job, err)
	}
	if err := f.accounts.FinishDelivery(ctx, *job, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.email_change_outbox SET available_at=clock_timestamp() WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	var newer *accountdomain.VerificationDelivery
	for range 3 {
		candidate, err := f.accounts.ClaimDelivery(ctx)
		if err != nil || candidate == nil {
			t.Fatal("retry claim", candidate, err)
		}
		if candidate.ID == job.ID {
			newer = candidate
			break
		}
		if err := f.accounts.FinishDelivery(ctx, *candidate, true); err != nil {
			t.Fatal(err)
		}
	}
	if newer == nil || newer.Attempts != 2 || newer.Lease == job.Lease {
		t.Fatal("missing retry lease", newer)
	}
	if err := f.accounts.FinishDelivery(ctx, *job, true); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.email_change_outbox WHERE id=$1 AND lease=$2)`, newer.ID, newer.Lease).Scan(&exists); err != nil || !exists {
		t.Fatal("stale lease acknowledged new job", exists, err)
	}
	if err := f.accounts.FinishDelivery(ctx, *newer, true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.email_changes SET created_at=clock_timestamp()-interval '3 days',expires_at=clock_timestamp()-interval '2 days',protect_until=clock_timestamp()-interval '1 day' WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.accounts.PurgeRetention(ctx, retentionPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
		t.Fatal("expired report accepted", err)
	}
	var intents, audit int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.email_changes WHERE user_id=$1),(SELECT count(*) FROM auth.email_change_audit WHERE user_id=$1)`, f.user).Scan(&intents, &audit); err != nil || intents != 0 || audit != 1 {
		t.Fatal("expiry lost audit or retained payload", intents, audit, err)
	}
	verification := accountdomain.Verification{Digest: strings.Repeat("8", 64), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
	other := newStatusFixture(t, db, ctx, "change-delivery-verification")
	if err := other.accounts.Issue(ctx, other.email, verification, 0); err != nil {
		t.Fatal(err)
	}
	change := newChangeFixture(t, db, ctx, "delivery-fairness")
	if err := change.request(ctx); err != nil {
		t.Fatal(err)
	}
	seenVerification, seenChange := false, false
	for range 2 {
		job, err := change.accounts.ClaimDelivery(ctx)
		if err != nil || job == nil {
			t.Fatal("fairness claim", job, err)
		}
		if job.EmailChange {
			seenChange = true
		} else {
			seenVerification = true
		}
		if err := change.accounts.FinishDelivery(ctx, *job, true); err != nil {
			t.Fatal(err)
		}
	}
	if !seenVerification || !seenChange {
		t.Fatal("one queue starved", seenVerification, seenChange)
	}
	if _, err := db.Exec(ctx, `ALTER TABLE auth.email_changes RENAME TO email_changes_disabled_fixture;
		ALTER TABLE auth.email_change_outbox RENAME TO email_change_outbox_disabled_fixture`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(ctx, `ALTER TABLE auth.email_changes_disabled_fixture RENAME TO email_changes;
			ALTER TABLE auth.email_change_outbox_disabled_fixture RENAME TO email_change_outbox`); err != nil {
			t.Error(err)
		}
	})
	if _, err := accountpostgres.New(db).ClaimDelivery(ctx); err != nil {
		t.Fatal("disabled profile queried email-change tables", err)
	}
}
