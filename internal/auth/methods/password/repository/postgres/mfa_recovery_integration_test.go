package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func recoveryService(t *testing.T, db *pgxpool.Pool, allow func(string, string) bool) *mfaservice.Recovery {
	t.Helper()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := mfaservice.NewRecovery(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, "Auth", mfaservice.LoginConfig{
		AllowPrimary: allow, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestMFARecoveryRequestSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_mfa_recovery_operator NOLOGIN;
		CREATE ROLE auth_mfa_schema_operator LOGIN PASSWORD 'synthetic-recovery-only';
		CREATE ROLE auth_mfa_schema_runtime LOGIN PASSWORD 'synthetic-recovery-only'`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `REVOKE CONNECT ON DATABASE auth_schema_test FROM auth_mfa_recovery_operator;
			DROP ROLE auth_mfa_schema_operator; DROP ROLE auth_mfa_schema_runtime; DROP ROLE auth_mfa_recovery_operator`)
	})
	grants, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "..", "deploy", "mfa-recovery-grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, strings.ReplaceAll(string(grants), "ON DATABASE auth TO", "ON DATABASE auth_schema_test TO"))
	accessExec(t, db, ctx, `GRANT auth_mfa_recovery_operator TO auth_mfa_schema_operator;
		GRANT USAGE ON SCHEMA auth TO auth_mfa_schema_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_mfa_schema_runtime`)
	opPool := operatorPool(t, ctx, db, "auth_mfa_schema_operator")
	op := mfapostgres.New(opPool)
	runtimeRepo := mfapostgres.New(operatorPool(t, ctx, db, "auth_mfa_schema_runtime"))
	svc := recoveryService(t, db, nil)
	f := newMFALoginFixture(t, db, ctx, "lost-factor")
	input := f.start(t, ctx)
	start := mfaservice.StartRecoveryInput{Token: input.Token, Binding: input.Binding, IP: input.IP}
	candidate, err := svc.Start(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	decision := mfadomain.RecoveryDecision{UserID: f.user, RequestID: candidate.RequestID, ExpectedVersion: 2, Environment: "test", Reason: "INC-MFA-42", Approve: true}
	var encrypted []byte
	if err := db.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeRepo.RecoveryTarget(ctx, f.user, candidate.RequestID); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("runtime metadata", err)
	}
	if err := runtimeRepo.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("runtime decision", err)
	}
	for _, query := range []string{
		`SELECT secret FROM auth.mfa_recovery_requests`,
		`SELECT secret FROM auth.mfa_totp`,
		`UPDATE auth.mfa_recovery_requests SET state='approved'`,
		`UPDATE auth.users SET auth_version=auth_version+1`,
		`SELECT primary_reference FROM auth.mfa_login_challenges`,
	} {
		expectSQLState(t, opPool, ctx, "42501", query)
	}
	target, err := op.RecoveryTarget(ctx, f.user, candidate.RequestID)
	if err != nil || target.AuthVersion != 2 || target.Operator != "auth_mfa_schema_operator" || target.Database != "auth_schema_test" || !target.ExpiresAt.Equal(candidate.ExpiresAt) {
		t.Fatal("metadata", target, err)
	}
	bad := start
	bad.Binding = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := svc.Start(ctx, bad); !errors.Is(err, mfadomain.ErrInvalidCode) {
		t.Fatal("foreign browser", err)
	}
	if _, err := recoveryService(t, db, func(string, string) bool { return false }).Start(ctx, start); !errors.Is(err, mfadomain.ErrInvalidCode) {
		t.Fatal("method policy", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_recovery_approval CHECK(event<>'recovery_approved') NOT VALID`)
	if err := op.DecideRecovery(ctx, decision); err == nil {
		t.Fatal("audit error committed")
	}
	var pending bool
	if err := db.QueryRow(ctx, `SELECT state='pending' AND operator_oid IS NULL FROM auth.mfa_recovery_requests WHERE user_id=$1`, f.user).Scan(&pending); err != nil || !pending {
		t.Fatal("approval rollback", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_recovery_approval`)
	var winners atomic.Int64
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			err := op.DecideRecovery(ctx, decision)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatal("approval winners", winners.Load())
	}
	var bound bool
	if err := db.QueryRow(ctx, `SELECT r.operator_oid=p.oid AND r.operator_name=p.rolname AND r.state='approved'
		AND r.reason='INC-MFA-42' AND r.environment='test' AND u.auth_version=2
		AND (SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=u.id)=10
		AND (SELECT count(*) FROM auth.mfa_audit WHERE request_id=r.request_id AND event='recovery_approved')=1
		FROM auth.mfa_recovery_requests r JOIN auth.users u ON u.id=r.user_id
		JOIN pg_catalog.pg_roles p ON p.rolname='auth_mfa_schema_operator' WHERE r.user_id=$1`, f.user).Scan(&bound); err != nil || !bound {
		t.Fatal("approval identity/invariants", err)
	}
	var after []byte
	if err := db.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&after); err != nil || !bytes.Equal(encrypted, after) {
		t.Fatal("old factor changed", err)
	}
	accessExec(t, db, ctx, `REVOKE auth_mfa_recovery_operator FROM auth_mfa_schema_operator`)
	decision.Approve = false
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("revoked operator", err)
	}
	accessExec(t, db, ctx, `GRANT auth_mfa_recovery_operator TO auth_mfa_schema_operator`)
	if err := op.DecideRecovery(ctx, decision); err != nil {
		t.Fatal("cancel", err)
	}
	decision.Approve = true
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("resurrected cancellation", err)
	}
	candidate2, err := svc.Start(ctx, start)
	if err != nil || candidate2.RequestID == candidate.RequestID || candidate2.Secret == candidate.Secret {
		t.Fatal("immutable reissue", err)
	}
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("old approval reused", err)
	}
	decision.RequestID = candidate2.RequestID
	decision.ExpectedVersion = 1
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("stale version", err)
	}
	decision.ExpectedVersion = 2
	if err := op.DecideRecovery(ctx, decision); err != nil {
		t.Fatal(err)
	}
	reissued, err := svc.Start(ctx, start)
	if err != nil || reissued.RequestID == decision.RequestID || !reissued.ExpiresAt.Equal(candidate2.ExpiresAt) {
		t.Fatal("reissue extends authority", err)
	}
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("approval moved to new candidate", err)
	}
	decision.RequestID = reissued.RequestID
	if err := db.QueryRow(ctx, `SELECT state='pending' AND operator_oid IS NULL FROM auth.mfa_recovery_requests WHERE user_id=$1`, f.user).Scan(&pending); err != nil || !pending {
		t.Fatal("reissue retained operator", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_recovery_start CHECK(event<>'recovery_requested') NOT VALID`)
	if _, err := svc.Start(ctx, start); err == nil {
		t.Fatal("unaudited candidate issued")
	}
	var preserved string
	if err := db.QueryRow(ctx, `SELECT request_id FROM auth.mfa_recovery_requests WHERE user_id=$1`, f.user).Scan(&preserved); err != nil || preserved != reissued.RequestID {
		t.Fatal("start rollback", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_recovery_start`)
	accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("blocked", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.users SET status='active' WHERE id=$1`, f.user)
	if _, err := f.login.Complete(ctx, input); err != nil {
		t.Fatal("normal MFA login", err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_recovery_requests WHERE user_id=$1`, f.user).Scan(&count); err != nil || count != 0 {
		t.Fatal("consumed challenge retained recovery", count, err)
	}
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("consumed challenge approved", err)
	}
	// Updating the existing primary challenge must discard its former candidate before the FK update.
	input = f.start(t, ctx)
	start = mfaservice.StartRecoveryInput{Token: input.Token, Binding: input.Binding, IP: input.IP}
	if _, err := svc.Start(ctx, start); err != nil {
		t.Fatal(err)
	}
	_ = f.start(t, ctx)
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_recovery_requests WHERE user_id=$1`, f.user).Scan(&count); err != nil || count != 0 {
		t.Fatal("new primary inherited recovery", err)
	}
	input = f.start(t, ctx)
	start = mfaservice.StartRecoveryInput{Token: input.Token, Binding: input.Binding, IP: input.IP}
	candidate, err = svc.Start(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	decision.RequestID = candidate.RequestID
	accessExec(t, db, ctx, `UPDATE auth.mfa_recovery_requests SET created_at=statement_timestamp()-interval '6 minutes',expires_at=statement_timestamp()-interval '1 minute' WHERE user_id=$1`, f.user)
	if err := op.DecideRecovery(ctx, decision); !errors.Is(err, mfadomain.ErrRecoveryOperatorDenied) {
		t.Fatal("expired", err)
	}
	t.Run("external-only", func(t *testing.T) {
		f := newMFALoginFixture(t, db, ctx, "lost-external")
		accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,'https://accounts.google.com','lost-external');
			`, f.user)
		accessExec(t, db, ctx, `DELETE FROM auth.password_credentials WHERE user_id=$1`, f.user)
		f.proof.Method, f.proof.Issuer, f.proof.Reference = "oidc", "https://accounts.google.com", "lost-external"
		input := f.start(t, ctx)
		start := mfaservice.StartRecoveryInput{Token: input.Token, Binding: input.Binding, IP: input.IP}
		external := recoveryService(t, db, func(method, issuer string) bool { return method == "oidc" && issuer == "https://accounts.google.com" })
		candidate, err := external.Start(ctx, start)
		if err != nil || candidate.RequestID == "" {
			t.Fatal("external primary", err)
		}
		accessExec(t, db, ctx, `DELETE FROM auth.linked_identities WHERE user_id=$1`, f.user)
		if _, err := external.Start(ctx, start); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("revoked identity", err)
		}
	})
}
