package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestAdministrativeLoginSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name) VALUES('delegated_admin','Delegated admin') RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'auth.settings.manage')`, role)
	prepare := func(t *testing.T, name string) mfaLoginFixture {
		f := newMFALoginFixture(t, db, ctx, name)
		f.proof.Administrative = true
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
		return f
	}
	t.Run("authority-kind", func(t *testing.T) {
		f := prepare(t, "product-only")
		accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, f.user)
		var productRole string
		if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name) VALUES('product_reader','Product reader') RETURNING id`).Scan(&productRole); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'products.read')`, productRole)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, productRole)
		if _, err := f.login.Start(ctx, f.proof, ""); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("product permission became administration", err)
		}
		var rootRole string
		if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&rootRole); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, rootRole)
		if _, err := f.login.Start(ctx, f.proof, ""); err != nil {
			t.Fatal("system administrator rejected", err)
		}
		expectSQLState(t, db, ctx, "23514", `UPDATE auth.mfa_login_challenges SET primary_method='oidc' WHERE user_id=$1`, f.user)
	})
	t.Run("provision-readiness", func(t *testing.T) {
		for _, state := range []string{"pending", "change-required", "temporary"} {
			f := prepare(t, "provision-"+state)
			accessExec(t, db, ctx, `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint,user_id) VALUES($1,gen_random_uuid(),repeat('a',64),$2)`, f.actor, f.user)
			if state != "pending" {
				accessExec(t, db, ctx, `UPDATE auth.account_provisions SET activated_at=clock_timestamp(),password_change_required=$2 WHERE user_id=$1`, f.user, state == "change-required")
			}
			if state == "temporary" {
				accessExec(t, db, ctx, `INSERT INTO auth.temporary_password_credentials(user_id,email_id,password_hash,secret_digest,auth_version,expires_at) SELECT user_id,email_id,'temporary',repeat('b',64),2,clock_timestamp()+interval '1 hour' FROM auth.password_credentials WHERE user_id=$1`, f.user)
			}
			if _, err := f.login.Start(ctx, f.proof, ""); !errors.Is(err, mfadomain.ErrProofRequired) {
				t.Fatal("unfinished provisioning accepted", state, err)
			}
		}
	})
	t.Run("mandatory-readiness", func(t *testing.T) {
		for i, query := range []string{
			`DELETE FROM auth.user_roles WHERE user_id=$1`,
			`UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`,
			`UPDATE auth.password_credentials SET password_hash='changed' WHERE user_id=$1`,
			`UPDATE auth.users SET status='blocked' WHERE id=$1`,
			`UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
			`DELETE FROM auth.mfa_totp WHERE user_id=$1`,
		} {
			f := prepare(t, "eligibility-"+string(rune('a'+i)))
			accessExec(t, db, ctx, query, f.user)
			if challenge, err := f.login.Start(ctx, f.proof, ""); challenge != nil || (!errors.Is(err, mfadomain.ErrProofRequired) && !errors.Is(err, mfadomain.ErrConflict)) {
				t.Fatal("ineligible admin accepted", i, err)
			}
		}
	})
	t.Run("atomic-completion-and-context", func(t *testing.T) {
		f := prepare(t, "admin-success")
		f.proof.VerifiedAt = time.Now().UTC().Add(-20 * time.Second)
		input := f.start(t, ctx)
		assertAdminSessionCount(t, db, ctx, f, 0)
		input.Binding = "wrong"
		if _, err := f.login.Complete(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("binding bypass", err)
		}
		input = f.start(t, ctx)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_admin_login CHECK(event<>'mfa_login_completed') NOT VALID`)
		if result, err := f.login.Complete(ctx, input); result != nil || err == nil {
			t.Fatal("audit failure committed")
		}
		assertAdminSessionCount(t, db, ctx, f, 0)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_admin_login`)
		result, err := f.login.Complete(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(result.Token))
		var passwordAt *time.Time
		if err := db.QueryRow(ctx, `SELECT password_verified_at FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(result.Token)).Scan(&passwordAt); err != nil {
			t.Fatal(err)
		}
		if err != nil || passwordAt == nil || stored.MFAVerifiedAt == nil || !passwordAt.Equal(*stored.PrimaryVerifiedAt) || passwordAt.After(time.Now().Add(-15*time.Second)) {
			t.Fatal("password time renewed or lost", stored, err)
		}
		if _, err := f.login.Complete(ctx, input); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("replay", err)
		}
		assertAdminSessionCount(t, db, ctx, f, 1)
	})
	t.Run("final-current-authority", func(t *testing.T) {
		for i, query := range []string{
			`DELETE FROM auth.user_roles WHERE user_id=$1`,
			`UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`,
			`UPDATE auth.password_credentials SET password_hash='changed' WHERE user_id=$1`,
			`UPDATE auth.users SET status='blocked' WHERE id=$1`,
			`UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
		} {
			f := prepare(t, "final-"+string(rune('a'+i)))
			input := f.start(t, ctx)
			accessExec(t, db, ctx, query, f.user)
			if result, err := f.login.Complete(ctx, input); result != nil || !errors.Is(err, mfadomain.ErrInvalidCode) {
				t.Fatal("stale admin proof accepted", i, err)
			}
			var codes int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1`, f.user).Scan(&codes); err != nil || codes != len(f.codes) {
				t.Fatal("denial consumed factor", codes, err)
			}
			assertAdminSessionCount(t, db, ctx, f, 0)
		}
	})
	t.Run("intent-replacement", func(t *testing.T) {
		f := prepare(t, "intent-replacement")
		old := f.start(t, ctx)
		f.proof.Administrative = false
		current := f.start(t, ctx)
		if _, err := f.login.Complete(ctx, old); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("replaced purpose accepted", err)
		}
		result, err := f.login.Complete(ctx, current)
		if err != nil {
			t.Fatal(err)
		}
		var passwordAt *time.Time
		err = db.QueryRow(ctx, `SELECT password_verified_at FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(result.Token)).Scan(&passwordAt)
		if err != nil || passwordAt != nil {
			t.Fatal("public login inherited private intent", err)
		}
	})
	t.Run("recovery-keeps-purpose", func(t *testing.T) {
		f := prepare(t, "admin-recovery")
		input := f.start(t, ctx)
		recovery := recoveryService(t, db, func(string, string) bool { return false })
		start := mfaservice.StartRecoveryInput{Token: input.Token, Binding: input.Binding, IP: input.IP}
		if _, err := recovery.Start(ctx, start); err != nil {
			t.Fatal("private recovery used public switch", err)
		}
		accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, f.user)
		if _, err := recovery.Start(ctx, start); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("recovery ignored revoked authority", err)
		}
	})
	t.Run("revocation-during-lock-wait", func(t *testing.T) {
		f := prepare(t, "admin-access-wait")
		input := f.start(t, ctx)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := f.login.Complete(ctx, input); done <- err }()
		waitForAdministrativeLock(t, db, ctx)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("committed revoke bypassed", err)
		}
		assertAdminSessionCount(t, db, ctx, f, 0)
	})
}

func assertAdminSessionCount(t *testing.T, db *pgxpool.Pool, ctx context.Context, f mfaLoginFixture, want int) {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL`, f.user).Scan(&count); err != nil || count != want {
		t.Fatal("unexpected session count", count, want, err)
	}
}

func waitForAdministrativeLock(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for time.Now().Before(deadline) {
		var waiting bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock(734013981)%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-poll.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	t.Fatal("completion did not wait for Access")
}

func checkAdministrativeRecoveryCompletion(t *testing.T, db, runtime *pgxpool.Pool, ctx context.Context, operator *mfapostgres.Repository) {
	t.Helper()
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name) VALUES('private_recovery_admin','Recovery administrator') RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'auth.settings.manage')`, role)
	for _, revoke := range []bool{false, true} {
		name := "private-recovery-success"
		if revoke {
			name = "private-recovery-revoked"
		}
		f := newMFALoginFixture(t, db, ctx, name)
		f.proof.Administrative = true
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
		primary := f.start(t, ctx)
		svc := recoveryService(t, runtime, func(string, string) bool { return false })
		candidate, err := svc.Start(ctx, mfaservice.StartRecoveryInput{Token: primary.Token, Binding: primary.Binding, IP: primary.IP})
		if err != nil {
			t.Fatal(err)
		}
		if err := operator.DecideRecovery(ctx, mfadomain.RecoveryDecision{UserID: f.user, RequestID: candidate.RequestID, ExpectedVersion: 2, Environment: "test", Reason: "INC-ADMIN-LOGIN", Approve: true}); err != nil {
			t.Fatal(err)
		}
		if revoke {
			accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, f.user)
		}
		result, err := svc.Complete(ctx, mfaservice.CompleteRecoveryInput{RequestID: candidate.RequestID, Token: primary.Token, Binding: primary.Binding, Code: mfaCode(t, db, ctx, candidate.Secret, 0), IP: primary.IP})
		wantVersion := int64(3)
		if revoke {
			wantVersion = 2
			if result != nil || !errors.Is(err, mfadomain.ErrInvalidCode) {
				t.Fatal("revoked admin recovered through private intent", err)
			}
		} else if err != nil || result == nil || len(result.Codes) != 10 {
			t.Fatal("private recovery used public method switch", err)
		}
		var version int64
		if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, f.user).Scan(&version); err != nil || version != wantVersion {
			t.Fatal("recovery committed unexpectedly", version, err)
		}
		assertAdminSessionCount(t, db, ctx, f, 0)
	}
}
