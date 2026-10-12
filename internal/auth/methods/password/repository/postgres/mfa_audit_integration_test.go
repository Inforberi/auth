package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func checkMFAConsumptionRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *mfaservice.Service) {
	t.Helper()
	f := newStatusFixture(t, db, ctx, "mfa-consume-rollback")
	proof := mfaProof(t, db, ctx, f)
	enrollment, err := svc.StartEnrollment(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)})
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_mfa_consume_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
		CREATE TRIGGER reject_mfa_consume_audit BEFORE INSERT ON auth.mfa_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_mfa_consume_audit()`)
	input := mfaservice.VerifyInput{UserID: f.user, AuthVersion: 2, Code: codes.Codes[0], Recovery: true}
	verified, err := svc.Verify(ctx, input)
	accessExec(t, db, ctx, `DROP TRIGGER reject_mfa_consume_audit ON auth.mfa_audit; DROP FUNCTION auth.reject_mfa_consume_audit()`)
	if err == nil || !verified.IsZero() {
		t.Fatal("factor accepted without audit")
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1`, f.user).Scan(&count); err != nil || count != 10 {
		t.Fatal("rollback burned recovery", count, err)
	}
	if _, err := svc.Verify(ctx, input); err != nil {
		t.Fatal("explicit retry after rollback", err)
	}
}
