package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type recoveryMailer struct {
	err      error
	to, body string
	calls    int
}

func (m *recoveryMailer) SendContext(_ context.Context, to, _, body string) error {
	m.to, m.body = to, body
	m.calls++
	return m.err
}

func recoveryQueue(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) changeFixture {
	t.Helper()
	f := protectedFixture(t, db, ctx, "delivery-"+name)
	if _, err := db.Exec(ctx, `DELETE FROM auth.email_verification_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM auth.email_change_outbox WHERE kind<>'recovery' OR change_id NOT IN
		(SELECT id FROM auth.email_changes WHERE user_id=$1)`, f.user); err != nil {
		t.Fatal(err)
	}
	return f
}

func checkProtectedRecoveryDelivery(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("worker-retry", func(t *testing.T) {
		f := recoveryQueue(t, db, ctx, "worker")
		cipher, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		if err != nil {
			t.Fatal(err)
		}
		body := "https://example.com/recover#token=fixture"
		payload, err := json.Marshal(map[string]string{"to": f.email, "subject": "Recovery", "body": body})
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := cipher.Seal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_change_outbox SET payload=$1 WHERE kind='recovery'`, sealed); err != nil {
			t.Fatal(err)
		}
		mail := &recoveryMailer{err: errors.New("SMTP unavailable")}
		worker := accountservice.New(f.accounts, nil, cipher, mail, accountservice.Config{})
		for attempt := 1; attempt <= 2; attempt++ {
			if err := worker.DeliverOne(ctx); !errors.Is(err, mail.err) {
				t.Fatal("delivery failure lost", err)
			}
			var attempts int
			var released bool
			var delay float64
			if err := db.QueryRow(ctx, `SELECT attempts,lease IS NULL,extract(epoch FROM available_at-clock_timestamp()) FROM auth.email_change_outbox WHERE kind='recovery'`).Scan(&attempts, &released, &delay); err != nil {
				t.Fatal(err)
			}
			want := float64(30 * attempt)
			if attempts != attempt || !released || delay < want-2 || delay > want {
				t.Fatal("retry state", attempts, released, delay)
			}
			if _, err := db.Exec(ctx, `UPDATE auth.email_change_outbox SET available_at=clock_timestamp()`); err != nil {
				t.Fatal(err)
			}
		}
		mail.err = nil
		if err := worker.DeliverOne(ctx); err != nil {
			t.Fatal(err)
		}
		if mail.calls != 3 || mail.to != f.email || mail.body != body {
			t.Fatal("wrong recovery recipient or payload", mail)
		}
		job, err := f.accounts.ClaimDelivery(ctx)
		if err != nil || job != nil {
			t.Fatal("delivered job retained", job, err)
		}
		if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); err != nil {
			t.Fatal("delivery consumed proof", err)
		}
	})
	t.Run("lease-and-admin-cancellation", func(t *testing.T) {
		f := recoveryQueue(t, db, ctx, "lease")
		first, err := f.accounts.ClaimDelivery(ctx)
		if err != nil || first == nil {
			t.Fatal(first, err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_change_outbox SET lease_until=clock_timestamp()-interval '1 second'`); err != nil {
			t.Fatal(err)
		}
		second, err := f.accounts.ClaimDelivery(ctx)
		if err != nil || second == nil || second.Lease == first.Lease || second.Attempts != 2 {
			t.Fatal(second, err)
		}
		if err := f.accounts.FinishDelivery(ctx, *first, true); err != nil {
			t.Fatal(err)
		}
		var retained bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.email_change_outbox WHERE id=$1 AND lease=$2)`, second.ID, second.Lease).Scan(&retained); err != nil || !retained {
			t.Fatal("stale acknowledgment removed lease", retained, err)
		}
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 3); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.FinishDelivery(ctx, *second, false); err != nil {
			t.Fatal(err)
		}
		job, err := f.accounts.ClaimDelivery(ctx)
		if err != nil || job != nil {
			t.Fatal("cancelled delivery resurrected", job, err)
		}
		if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
			t.Fatal("cancelled proof valid", err)
		}
	})
	t.Run("exhaustion-and-expiry", func(t *testing.T) {
		f := recoveryQueue(t, db, ctx, "exhausted")
		for attempt := 1; attempt <= 5; attempt++ {
			job, err := f.accounts.ClaimDelivery(ctx)
			if err != nil || job == nil || job.Attempts != attempt {
				t.Fatal("attempt", attempt, job, err)
			}
			if err := f.accounts.FinishDelivery(ctx, *job, false); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `UPDATE auth.email_change_outbox SET available_at=clock_timestamp()`); err != nil {
				t.Fatal(err)
			}
		}
		job, err := f.accounts.ClaimDelivery(ctx)
		if err != nil || job != nil {
			t.Fatal("exhausted job retried", job, err)
		}
		if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); err != nil {
			t.Fatal("SMTP failure changed proof", err)
		}
		f = recoveryQueue(t, db, ctx, "expired")
		if _, err := db.Exec(ctx, `UPDATE auth.email_changes SET recovery_expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_change_outbox SET expires_at=clock_timestamp()-interval '1 second'`); err != nil {
			t.Fatal(err)
		}
		job, err = f.accounts.ClaimDelivery(ctx)
		if err != nil || job != nil {
			t.Fatal("expired mail claimed", job, err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement"); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
			t.Fatal("expired proof accepted", err)
		}
		var status string
		if err := db.QueryRow(ctx, `SELECT status FROM auth.users WHERE id=$1`, f.user).Scan(&status); err != nil || status != string(accountdomain.StatusBlocked) {
			t.Fatal("expiry unblocked user", status, err)
		}
	})
}
