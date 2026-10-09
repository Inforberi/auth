package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func checkVerificationFailures(t *testing.T, db *pgxpool.Pool, ctx context.Context, password *PasswordRepo, svc *accountservice.Service, repo *accountpostgres.Repository, cipher *secretbox.Cipher, last *domain.Verification) {
	t.Helper()
	user, err := password.CreateUser(ctx, "audit-failure@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	token := verificationToken(t, cipher, *last)
	if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_test_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
		CREATE TRIGGER reject_test_audit BEFORE INSERT ON auth.email_verification_audit FOR EACH ROW WHEN (NEW.event='email_verified') EXECUTE FUNCTION auth.reject_test_audit()`); err != nil {
		t.Fatal(err)
	}
	err = svc.Confirm(ctx, token, "ip")
	if err == nil || errors.Is(err, domain.ErrInvalidVerification) {
		t.Fatal("audit failure was not a dependency error", err)
	}
	if !errors.Is(svc.RequireVerified(ctx, user), domain.ErrEmailUnverified) {
		t.Fatal("audit failure committed verification")
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER reject_test_audit ON auth.email_verification_audit; DROP FUNCTION auth.reject_test_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Confirm(ctx, token, "ip"); err != nil {
		t.Fatal("audit failure consumed token", err)
	}

	user, err = password.CreateUser(ctx, "blocked-verification@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	token = verificationToken(t, cipher, *last)
	if _, err := db.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(svc.Confirm(ctx, token, "ip"), domain.ErrInvalidVerification) {
		t.Fatal("blocked account verified")
	}
	if job, err := repo.ClaimDelivery(ctx); err != nil || job != nil {
		t.Fatal("blocked account mail claimed", err)
	}

	if _, err := password.CreateUser(ctx, "delivery-failure@example.com", "hash"); err != nil {
		t.Fatal(err)
	}
	first, err := repo.ClaimDelivery(ctx)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.email_verification_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := repo.ClaimDelivery(ctx)
	if err != nil || second == nil || second.Lease == first.Lease {
		t.Fatal("stale lease not replaced", err)
	}
	if err := repo.FinishDelivery(ctx, *first, true); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_verification_outbox WHERE id=$1`, first.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("stale worker removed live lease", err)
	}
	if err := repo.FinishDelivery(ctx, *second, false); err != nil {
		t.Fatal(err)
	}
	for expected := 3; expected <= 5; expected++ {
		if _, err := db.Exec(ctx, `UPDATE auth.email_verification_outbox SET available_at=clock_timestamp() WHERE id=$1`, first.ID); err != nil {
			t.Fatal(err)
		}
		job, err := repo.ClaimDelivery(ctx)
		if err != nil || job == nil || job.Attempts != expected {
			t.Fatal("unexpected retry", err)
		}
		if err := repo.FinishDelivery(ctx, *job, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_verification_outbox WHERE id=$1`, first.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("terminal ciphertext retained", err)
	}
}
