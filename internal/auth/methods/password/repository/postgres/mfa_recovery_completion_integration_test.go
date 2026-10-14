package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type lostFactorFixture struct {
	mfaLoginFixture
	svc       *mfaservice.Recovery
	candidate *mfaservice.RecoveryCandidate
	input     mfaservice.CompleteRecoveryInput
	decision  mfadomain.RecoveryDecision
}

func prepareLostFactor(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string, verified bool) lostFactorFixture {
	t.Helper()
	f := newMFALoginFixture(t, db, ctx, "completion-"+name)
	if verified {
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=NULL,auth_version=2 WHERE user_id=$1`, f.user)
	primary := f.start(t, ctx)
	svc := recoveryService(t, db, nil)
	candidate, err := svc.Start(ctx, mfaservice.StartRecoveryInput{Token: primary.Token, Binding: primary.Binding, IP: primary.IP})
	if err != nil {
		t.Fatal(err)
	}
	return lostFactorFixture{
		mfaLoginFixture: f, svc: svc, candidate: candidate,
		input:    mfaservice.CompleteRecoveryInput{RequestID: candidate.RequestID, Token: primary.Token, Binding: primary.Binding, Code: mfaCode(t, db, ctx, candidate.Secret, 0), IP: primary.IP},
		decision: mfadomain.RecoveryDecision{UserID: f.user, RequestID: candidate.RequestID, ExpectedVersion: 2, Environment: "test", Reason: "INC-COMPLETE", Approve: true},
	}
}

func assertLostFactorIntact(t *testing.T, db *pgxpool.Pool, ctx context.Context, f lostFactorFixture) {
	t.Helper()
	var intact bool
	if err := db.QueryRow(ctx, `SELECT u.auth_version=2 AND
		(SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=u.id)=10
		AND EXISTS(SELECT 1 FROM auth.mfa_recovery_codes WHERE user_id=u.id AND digest=$2)
		AND EXISTS(SELECT 1 FROM auth.mfa_recovery_requests WHERE user_id=u.id)
		AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_outbox WHERE user_id=u.id)
		AND NOT EXISTS(SELECT 1 FROM auth.mfa_audit WHERE user_id=u.id AND event='recovery_completed')
		AND EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=u.id AND revoked_at IS NULL)
		FROM auth.users u WHERE u.id=$1`, f.user, mfaRecoveryDigest(t, f.user, f.codes[0])).Scan(&intact); err != nil || !intact {
		t.Fatal("partial recovery", err)
	}
}

func recoveryCipher(t *testing.T) *secretbox.Cipher {
	t.Helper()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func mfaRecoveryDigest(t *testing.T, user accountdomain.UserID, code string) string {
	t.Helper()
	return recoveryCipher(t).Digest("recovery:" + string(user) + ":" + code)
}

func TestMFARecoveryCompletionSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_mfa_recovery_operator NOLOGIN;
		CREATE ROLE auth_mfa_completion_operator LOGIN PASSWORD 'synthetic-recovery-only';
		CREATE ROLE auth_mfa_completion_runtime LOGIN PASSWORD 'synthetic-recovery-only'`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `REVOKE CONNECT ON DATABASE auth_schema_test FROM auth_mfa_recovery_operator;
			DROP ROLE auth_mfa_completion_operator; DROP ROLE auth_mfa_completion_runtime; DROP ROLE auth_mfa_recovery_operator`)
	})
	grants, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "..", "deploy", "mfa-recovery-grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, strings.ReplaceAll(string(grants), "ON DATABASE auth TO", "ON DATABASE auth_schema_test TO"))
	accessExec(t, db, ctx, `GRANT auth_mfa_recovery_operator TO auth_mfa_completion_operator`)
	accessExec(t, db, ctx, `GRANT USAGE ON SCHEMA auth TO auth_mfa_completion_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_mfa_completion_runtime`)
	opPool := operatorPool(t, ctx, db, "auth_mfa_completion_operator")
	op := mfapostgres.New(opPool)
	t.Run("race-atomicity-and-normal-login", func(t *testing.T) {
		f := prepareLostFactor(t, db, ctx, "race", true)
		var role string
		if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&role); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
		accessExec(t, db, ctx, `INSERT INTO auth.initial_setup(singleton,initialized_at,administrator_id) VALUES(true,clock_timestamp(),$1)`, f.user)
		if err := op.DecideRecovery(ctx, f.decision); err != nil {
			t.Fatal(err)
		}
		var before []byte
		if err := db.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for _, failure := range []string{"audit", "outbox"} {
			if failure == "audit" {
				accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_completion CHECK(event<>'recovery_completed') NOT VALID`)
			} else {
				accessExec(t, db, ctx, `ALTER TABLE auth.mfa_recovery_outbox ADD CONSTRAINT reject_completion CHECK(false) NOT VALID`)
			}
			if result, err := f.svc.Complete(ctx, f.input); err == nil || result != nil {
				t.Fatal("failure accepted", failure)
			}
			assertLostFactorIntact(t, db, ctx, f)
			if failure == "audit" {
				accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_completion`)
			} else {
				accessExec(t, db, ctx, `ALTER TABLE auth.mfa_recovery_outbox DROP CONSTRAINT reject_completion`)
			}
		}
		var winners atomic.Int64
		var group sync.WaitGroup
		results := make(chan *mfaservice.RecoveryCodes, 16)
		for range 16 {
			group.Go(func() {
				result, err := f.svc.Complete(ctx, f.input)
				if err == nil {
					winners.Add(1)
					results <- result
				} else if !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Error(err)
				}
			})
		}
		group.Wait()
		close(results)
		if winners.Load() != 1 {
			t.Fatal("completion winner count", winners.Load())
		}
		codes := <-results
		var secret []byte
		var clean bool
		if err := db.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&secret); err != nil || bytes.Equal(secret, before) {
			t.Fatal("factor not replaced", err)
		}
		if err := db.QueryRow(ctx, `SELECT u.auth_version=3 AND u.access_version=1 AND u.status='active'
			AND (SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=u.id)=10
			AND NOT EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=u.id AND revoked_at IS NULL)
			AND NOT EXISTS(SELECT 1 FROM auth.mfa_login_challenges WHERE user_id=u.id)
			AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_requests WHERE user_id=u.id)
			AND EXISTS(SELECT 1 FROM auth.mfa_recovery_outbox WHERE user_id=u.id AND request_id=$2)
			AND EXISTS(SELECT 1 FROM auth.mfa_audit WHERE user_id=u.id AND event='recovery_completed'
				AND auth_version=3 AND operator_name='auth_mfa_completion_operator' AND notification_queued)
			AND EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=u.id AND password_hash='old-hash')
			AND EXISTS(SELECT 1 FROM auth.initial_setup WHERE administrator_id=u.id AND initialized_at IS NOT NULL)
			FROM auth.users u WHERE u.id=$1`, f.user, f.input.RequestID).Scan(&clean); err != nil || !clean {
			t.Fatal("completion invariants", err)
		}
		assertAdministratorRole(t, db, ctx, f.user, role, "active")
		f.proof.AuthVersion = 3
		primary := f.start(t, ctx)
		if _, err := f.login.Complete(ctx, primary); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("old recovery retained", err)
		}
		primary.Code = codes.Codes[0]
		if _, err := f.login.Complete(ctx, primary); err != nil {
			t.Fatal("new recovery login", err)
		}
		if result, err := f.svc.Complete(ctx, f.input); !errors.Is(err, mfadomain.ErrInvalidCode) || result != nil {
			t.Fatal("completion replay", err)
		}
		checkMFARecoveryDelivery(t, db, ctx, f)
	})
	checkMFARecoveryHTTP(t, db, operatorPool(t, ctx, db, "auth_mfa_completion_runtime"), ctx, op)
	checkMFARecoveryRaces(t, db, ctx, op)
	checkMFARecoveryCompletionGuards(t, db, ctx, op)
}
