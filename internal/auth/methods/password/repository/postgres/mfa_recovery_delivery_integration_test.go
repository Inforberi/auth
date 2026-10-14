package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func checkMFARecoveryDelivery(t *testing.T, db *pgxpool.Pool, ctx context.Context, f lostFactorFixture) {
	t.Helper()
	repo := mfapostgres.New(db)
	var payload []byte
	if err := db.QueryRow(ctx, `SELECT payload FROM auth.mfa_recovery_outbox WHERE user_id=$1`, f.user).Scan(&payload); err != nil || bytes.Contains(payload, []byte(f.email)) {
		t.Fatal("encrypted notification", err)
	}
	// A committed security event goes to its verified snapshot, not the current contact/version.
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET email='changed-'||email WHERE user_id=$1`, f.user)
	accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, f.user)
	accessExec(t, db, ctx, `UPDATE auth.mfa_audit SET created_at=statement_timestamp()-interval '2 days' WHERE user_id=$1`, f.user)
	retention := accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 1, BatchSize: 100}
	if _, err := f.accounts.PurgeRetention(ctx, retention); err != nil {
		t.Fatal(err)
	}
	claims := make(chan *mfadomain.RecoveryDelivery, 16)
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			job, err := repo.ClaimRecoveryDelivery(ctx)
			if err != nil {
				t.Error(err)
			}
			if job != nil {
				claims <- job
			}
		})
	}
	group.Wait()
	close(claims)
	if len(claims) != 1 {
		t.Fatal("duplicate notification lease", len(claims))
	}
	first := <-claims
	accessExec(t, db, ctx, `UPDATE auth.mfa_recovery_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, first.ID)
	second, err := repo.ClaimRecoveryDelivery(ctx)
	if err != nil || second == nil || first.Lease == second.Lease || second.Attempts != 2 {
		t.Fatal("lease reclaim", second, err)
	}
	if err := repo.FinishRecoveryDelivery(ctx, *first, true); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_recovery_outbox WHERE id=$1 AND lease=$2)`, second.ID, second.Lease).Scan(&exists); err != nil || !exists {
		t.Fatal("stale ack deleted notification", err)
	}
	if err := repo.FinishRecoveryDelivery(ctx, *second, false); err != nil {
		t.Fatal(err)
	}
	mail := &recoveryMailer{err: errors.New("SMTP outage")}
	worker, err := mfaservice.NewRecoveryDelivery(repo, recoveryCipher(t), mail)
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := worker.DeliverOne(ctx); err != nil || processed {
		t.Fatal("retry ignored backoff", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.mfa_recovery_outbox SET available_at=clock_timestamp() WHERE id=$1`, second.ID)
	if processed, err := worker.DeliverOne(ctx); !processed || !errors.Is(err, mfadomain.ErrRecoveryDelivery) {
		t.Fatal("SMTP failure", err)
	}
	if mail.to != f.email || strings.Contains(mail.body, f.candidate.Secret) || strings.Contains(mail.body, "href=") {
		t.Fatal("wrong security notice recipient/body")
	}
	mail.err = nil
	accessExec(t, db, ctx, `UPDATE auth.mfa_recovery_outbox SET available_at=clock_timestamp() WHERE id=$1`, second.ID)
	if processed, err := worker.DeliverOne(ctx); !processed || err != nil {
		t.Fatal("SMTP retry", err)
	}
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_recovery_outbox WHERE id=$1)`, second.ID).Scan(&exists); err != nil || exists {
		t.Fatal("delivered ciphertext retained", err)
	}
	mail.err = errors.New("persistent outage")
	var failedID string
	if err := db.QueryRow(ctx, `INSERT INTO auth.mfa_recovery_outbox(user_id,request_id,payload) VALUES($1,gen_random_uuid(),$2) RETURNING id`, f.user, payload).Scan(&failedID); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if _, err := worker.DeliverOne(ctx); !errors.Is(err, mfadomain.ErrRecoveryDelivery) {
			t.Fatal("failed retry", i, err)
		}
		if i < 5 {
			accessExec(t, db, ctx, `UPDATE auth.mfa_recovery_outbox SET available_at=clock_timestamp() WHERE id=$1`, failedID)
		}
	}
	if err := db.QueryRow(ctx, `SELECT attempts=5 AND failed_at IS NOT NULL AND lease IS NULL AND payload=$2 FROM auth.mfa_recovery_outbox WHERE id=$1`, failedID, payload).Scan(&exists); err != nil || !exists {
		t.Fatal("failed notice silently deleted", err)
	}
	if _, err := f.accounts.PurgeRetention(ctx, retention); err != nil {
		t.Fatal(err)
	}
	if job, err := repo.ClaimRecoveryDelivery(ctx); err != nil || job != nil {
		t.Fatal("dead letter retries forever", err)
	}
	var abandonedID string
	if err := db.QueryRow(ctx, `INSERT INTO auth.mfa_recovery_outbox(user_id,request_id,payload,attempts) VALUES($1,gen_random_uuid(),$2,4) RETURNING id`, f.user, payload).Scan(&abandonedID); err != nil {
		t.Fatal(err)
	}
	last, err := repo.ClaimRecoveryDelivery(ctx)
	if err != nil || last == nil || last.Attempts != 5 || last.Exhausted {
		t.Fatal("last lease", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.mfa_recovery_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, abandonedID)
	before := mail.calls
	if _, err := worker.DeliverOne(ctx); !errors.Is(err, mfadomain.ErrRecoveryDelivery) || mail.calls != before {
		t.Fatal("sixth SMTP attempt after crash", err)
	}
	if err := db.QueryRow(ctx, `SELECT failed_at IS NOT NULL AND lease IS NULL FROM auth.mfa_recovery_outbox WHERE id=$1`, abandonedID).Scan(&exists); err != nil || !exists {
		t.Fatal("abandoned lease not retained", err)
	}
}
