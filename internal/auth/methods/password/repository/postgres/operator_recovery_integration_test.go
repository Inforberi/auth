package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func operatorPool(t *testing.T, ctx context.Context, owner *pgxpool.Pool, user string) *pgxpool.Pool {
	t.Helper()
	cfg := owner.Config()
	cfg.ConnConfig.User = user
	cfg.ConnConfig.Password = "synthetic-recovery-only"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestOperatorRecoverySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_recovery_operator NOLOGIN;
		CREATE ROLE auth_schema_operator LOGIN PASSWORD 'synthetic-recovery-only';
		CREATE ROLE auth_schema_runtime LOGIN PASSWORD 'synthetic-recovery-only'`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `REVOKE CONNECT ON DATABASE auth_schema_test FROM auth_recovery_operator;
			DROP ROLE auth_schema_operator; DROP ROLE auth_schema_runtime; DROP ROLE auth_recovery_operator`)
	})
	grants, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "..", "deploy", "recovery-grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, strings.ReplaceAll(string(grants), "ON DATABASE auth TO", "ON DATABASE auth_schema_test TO"))
	accessExec(t, db, ctx, `GRANT auth_recovery_operator TO auth_schema_operator;
		GRANT USAGE ON SCHEMA auth TO auth_schema_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_schema_runtime`)
	op := New(operatorPool(t, ctx, db, "auth_schema_operator"))
	runtimeRepo := New(operatorPool(t, ctx, db, "auth_schema_runtime"))
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	factorFixture := newMFALoginFixture(t, db, ctx, "operator-recovery")
	f := factorFixture.statusFixture
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
	accessExec(t, db, ctx, `INSERT INTO auth.initial_setup(singleton,initialized_at,administrator_id) VALUES(true,clock_timestamp(),$1)`, f.user)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=NULL,auth_version=2 WHERE user_id=$1`, f.user)
	request := passworddomain.OperatorRecovery{UserID: f.user, ExpectedVersion: 2, Environment: "test", Reason: "INC-123"}
	if _, err := runtimeRepo.OperatorRecoveryTarget(ctx, f.user); !errors.Is(err, passworddomain.ErrOperatorRecoveryDenied) {
		t.Fatal("runtime preview", err)
	}
	if _, err := runtimeRepo.ResetAdministratorPassword(ctx, request, "replacement"); !errors.Is(err, passworddomain.ErrOperatorRecoveryDenied) {
		t.Fatal("runtime reset", err)
	}
	if _, err := op.OperatorRecoveryTarget(ctx, f.actor); !errors.Is(err, passworddomain.ErrOperatorRecoveryDenied) {
		t.Fatal("non-admin target", err)
	}
	target, err := op.OperatorRecoveryTarget(ctx, f.user)
	if err != nil || target.AuthVersion != 2 || target.Operator != "auth_schema_operator" || target.Database != "auth_schema_test" {
		t.Fatal("operator identity", target, err)
	}
	var beforeSecret []byte
	var beforeStep int64
	if err := db.QueryRow(ctx, `SELECT secret,last_step FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&beforeSecret, &beforeStep); err != nil {
		t.Fatal(err)
	}
	challenge := passworddomain.ResetChallenge{Digest: tokengenerate.New().Hash("operator-old-reset"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
	if err := f.passwords.IssueReset(ctx, f.email, challenge); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_enrollments(user_id,digest,auth_version,session_hash,secret,expires_at)
		VALUES($1,repeat('a',64),2,$2,$3,statement_timestamp()+interval '5 minutes')`, f.user, f.params.TokenHash, beforeSecret)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_login_challenges(user_id,digest,binding_hash,auth_version,primary_method,primary_reference,primary_issuer,primary_verified_at,expires_at)
		VALUES($1,repeat('b',64),repeat('c',64),2,'password','old-hash','',statement_timestamp(),statement_timestamp()+interval '5 minutes')`, f.user)
	accessExec(t, db, ctx, `INSERT INTO auth.email_login_challenges(digest,user_id,email_id,auth_version,verifier,expires_at)
		SELECT repeat('d',64),$1,id,2,repeat('e',64),statement_timestamp()+interval '5 minutes' FROM auth.user_emails WHERE user_id=$1`, f.user)
	// No credentials/version/session/challenge changes may survive an audit failure.
	accessExec(t, db, ctx, `ALTER TABLE auth.password_audit ADD CONSTRAINT reject_operator_audit CHECK(event<>'operator_password_reset') NOT VALID`)
	if _, err := op.ResetAdministratorPassword(ctx, request, "replacement"); err == nil {
		t.Fatal("audit failure accepted")
	}
	var intact bool
	if err := db.QueryRow(ctx, `SELECT auth_version=2 AND EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1 AND password_hash='old-hash')
		AND EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL)
		AND EXISTS(SELECT 1 FROM auth.password_resets WHERE user_id=$1) FROM auth.users WHERE id=$1`, f.user).Scan(&intact); err != nil || !intact {
		t.Fatal("partial reset on audit error", err)
	}
	accessExec(t, db, ctx, `ALTER TABLE auth.password_audit DROP CONSTRAINT reject_operator_audit`)
	var winners atomic.Int64
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Go(func() {
			version, err := op.ResetAdministratorPassword(ctx, request, "replacement")
			if err == nil && version == 3 {
				winners.Add(1)
			} else if !errors.Is(err, passworddomain.ErrOperatorRecoveryConflict) {
				t.Error("concurrent reset", err, version)
			}
		})
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatal("reset winner count", winners.Load())
	}
	assertAdministratorRole(t, db, ctx, f.user, role, "active")
	var pending, audits, codes int
	if err := db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM auth.password_resets WHERE user_id=$1)+(SELECT count(*) FROM auth.mfa_enrollments WHERE user_id=$1)+
		(SELECT count(*) FROM auth.mfa_login_challenges WHERE user_id=$1)+(SELECT count(*) FROM auth.email_login_challenges WHERE user_id=$1),
		(SELECT count(*) FROM auth.password_audit WHERE user_id=$1 AND event='operator_password_reset' AND operator_name='auth_schema_operator' AND environment='test' AND reason='INC-123' AND auth_version=3),
		(SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1)`, f.user).Scan(&pending, &audits, &codes); err != nil || pending != 0 || audits != 1 || codes != 10 {
		t.Fatal("cleanup/audit/MFA", err, pending, audits, codes)
	}
	var afterSecret []byte
	var afterStep int64
	if err := db.QueryRow(ctx, `SELECT secret,last_step FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&afterSecret, &afterStep); err != nil || !bytes.Equal(beforeSecret, afterSecret) || beforeStep != afterStep {
		t.Fatal("factor changed", err)
	}
	if _, err := op.ResetAdministratorPassword(ctx, request, "replay"); !errors.Is(err, passworddomain.ErrOperatorRecoveryConflict) {
		t.Fatal("replay", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
	request.ExpectedVersion = 3
	if version, err := op.ResetAdministratorPassword(ctx, request, "blocked-replacement"); err != nil || version != 4 {
		t.Fatal("blocked password reset", version, err)
	}
	assertAdministratorRole(t, db, ctx, f.user, role, "blocked")
	var initialized bool
	if err := db.QueryRow(ctx, `SELECT initialized_at IS NOT NULL AND administrator_id=$1 FROM auth.initial_setup`, f.user).Scan(&initialized); err != nil || !initialized {
		t.Fatal("setup marker reset", err)
	}
	if _, err := op.OperatorRecoveryTarget(ctx, f.user); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `REVOKE auth_recovery_operator FROM auth_schema_operator`)
	request.ExpectedVersion = 4
	if _, err := op.ResetAdministratorPassword(ctx, request, "revoked-operator"); err == nil {
		t.Fatal("revoked database operator accepted")
	}
	accessExec(t, db, ctx, `GRANT auth_recovery_operator TO auth_schema_operator`)
	accessExec(t, db, ctx, `UPDATE auth.users SET deleted_at=clock_timestamp() WHERE id=$1`, f.user)
	request.ExpectedVersion = 4
	if _, err := op.ResetAdministratorPassword(ctx, request, "deleted-replacement"); !errors.Is(err, passworddomain.ErrOperatorRecoveryDenied) {
		t.Fatal("deleted admin recovered", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.users SET deleted_at=NULL WHERE id=$1`, f.user)
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, f.user)
	if _, err := op.ResetAdministratorPassword(ctx, request, "demoted-replacement"); !errors.Is(err, passworddomain.ErrOperatorRecoveryDenied) {
		t.Fatal("demoted admin recovered", err)
	}
}
