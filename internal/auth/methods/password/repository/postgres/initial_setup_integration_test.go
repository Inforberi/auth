package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
)

func TestInitialSetupSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	r := accountpostgres.New(db)
	operator, request := strings.Repeat("a", 64), strings.Repeat("b", 64)
	payload := bytes.Repeat([]byte{1}, 64)
	account := &accountdomain.SetupAccount{UserID: "11111111-1111-4111-8111-111111111111", Email: "setup@example.test", PasswordHash: "synthetic-hash", Factor: bytes.Repeat([]byte{1}, 64), LastStep: 123456}
	for i := 0; i < 10; i++ {
		account.RecoveryDigests = append(account.RecoveryDigests, fmt.Sprintf("%064x", i))
	}
	check := func(got []byte, _ time.Time) (*accountdomain.SetupAccount, error) {
		if !bytes.Equal(got, payload) {
			return nil, errors.New("changed encrypted payload")
		}
		return account, nil
	}
	if err := r.CheckSetupOpen(ctx); err != nil {
		t.Fatal(err)
	}
	expires, err := r.SaveSetup(ctx, operator, request, payload)
	if err != nil || expires.Before(time.Now()) {
		t.Fatal(err)
	}
	if _, err := r.SaveSetup(ctx, operator, request, payload); !errors.Is(err, accountdomain.ErrSetupConflict) {
		t.Fatal("cooldown", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.initial_setup SET created_at=created_at-interval '1 minute',expires_at=expires_at-interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SaveSetup(ctx, strings.Repeat("c", 64), request, payload); !errors.Is(err, accountdomain.ErrSetupConflict) {
		t.Fatal("operator pin", err)
	}
	if err := r.CompleteSetup(ctx, operator, strings.Repeat("c", 64), check); !errors.Is(err, accountdomain.ErrSetupInvalid) {
		t.Fatal("foreign intent", err)
	}
	if err := r.CompleteSetup(ctx, strings.Repeat("c", 64), request, check); !errors.Is(err, accountdomain.ErrSetupInvalid) {
		t.Fatal("foreign operator", err)
	}
	wrong := func([]byte, time.Time) (*accountdomain.SetupAccount, error) {
		return nil, accountdomain.ErrSetupInvalid
	}
	for i := 0; i < 5; i++ {
		if err := r.CompleteSetup(ctx, operator, request, wrong); !errors.Is(err, accountdomain.ErrSetupInvalid) {
			t.Fatal(err)
		}
	}
	var attempts int
	if err := db.QueryRow(ctx, `SELECT attempts FROM auth.initial_setup`).Scan(&attempts); err != nil || attempts != 5 {
		t.Fatal("attempts not committed", err)
	}
	if err := r.CompleteSetup(ctx, operator, request, check); !errors.Is(err, accountdomain.ErrSetupInvalid) {
		t.Fatal("attempt cap", err)
	}
	if _, err := r.SaveSetup(ctx, operator, request, payload); err != nil {
		t.Fatal("reissue", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.initial_setup SET created_at=statement_timestamp()-interval '11 minutes',expires_at=statement_timestamp()-interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteSetup(ctx, operator, request, check); !errors.Is(err, accountdomain.ErrSetupInvalid) {
		t.Fatal("expiry", err)
	}
	if _, err := r.SaveSetup(ctx, operator, request, payload); err != nil {
		t.Fatal(err)
	}
	// A unique email conflict must not merge with an existing account or leave the candidate user.
	var existing, contact string
	if err := db.QueryRow(ctx, `INSERT INTO auth.users DEFAULT VALUES RETURNING id`).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES($1,$2) RETURNING id`, existing, account.Email).Scan(&contact); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteSetup(ctx, operator, request, check); !errors.Is(err, accountdomain.ErrSetupConflict) {
		t.Fatal("email collision", err)
	}
	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.users WHERE id=$1)`, account.UserID).Scan(&exists); err != nil || exists {
		t.Fatal("partial account on collision", err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM auth.user_emails WHERE id=$1`, contact); err != nil {
		t.Fatal(err)
	}
	// Audit failure rolls back the user, factor, system role, grant and installation marker together.
	if _, err := db.Exec(ctx, `ALTER TABLE auth.access_audit ADD CONSTRAINT setup_audit_failure CHECK(false) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteSetup(ctx, operator, request, check); err == nil {
		t.Fatal("audit failure accepted")
	}
	if err := r.CheckSetupOpen(ctx); err != nil {
		t.Fatal("marker committed on audit failure", err)
	}
	var users, roles, factors int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.users WHERE id=$1),(SELECT count(*) FROM auth.roles WHERE system),(SELECT count(*) FROM auth.mfa_totp WHERE user_id=$1)`, account.UserID).Scan(&users, &roles, &factors); err != nil || users+roles+factors != 0 {
		t.Fatal("partial privileged state", err)
	}
	if _, err := db.Exec(ctx, `ALTER TABLE auth.access_audit DROP CONSTRAINT setup_audit_failure`); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int64
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Go(func() {
			err := r.CompleteSetup(ctx, operator, request, check)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, accountdomain.ErrSetupClosed) {
				t.Error("concurrent completion", err)
			}
		})
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatal("winner count", winners.Load())
	}
	var email, factor, codes, audits, permissions int
	if err := db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM auth.user_emails WHERE user_id=$1 AND verified_at IS NOT NULL),
		(SELECT count(*) FROM auth.mfa_totp WHERE user_id=$1 AND last_step=123456),
		(SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1),
		(SELECT count(*) FROM auth.access_audit WHERE target_id=$1),
		(SELECT count(*) FROM auth.role_permissions rp JOIN auth.user_roles ur ON ur.role_id=rp.role_id WHERE ur.user_id=$1)`, account.UserID).Scan(&email, &factor, &codes, &audits, &permissions); err != nil || email != 1 || factor != 1 || codes != 10 || audits != 1 || permissions != 7 {
		t.Fatal("incomplete setup", err, email, factor, codes, audits, permissions)
	}
	var erased bool
	if err := db.QueryRow(ctx, `SELECT initialized_at IS NOT NULL AND payload IS NULL AND operator_hash IS NULL AND request_hash IS NULL FROM auth.initial_setup`).Scan(&erased); err != nil || !erased {
		t.Fatal("pending secrets retained", err)
	}
	if _, err := r.SaveSetup(ctx, operator, request, payload); !errors.Is(err, accountdomain.ErrSetupClosed) {
		t.Fatal("start after complete", err)
	}
	if err := r.CompleteSetup(ctx, operator, request, check); !errors.Is(err, accountdomain.ErrSetupClosed) {
		t.Fatal("replay", err)
	}
	// Simulate loss of all system assignments and a process restart. Never reopen setup.
	if _, err := db.Exec(ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, account.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`, account.UserID); err != nil {
		t.Fatal(err)
	}
	if err := accountpostgres.New(db).CheckSetupOpen(context.Background()); !errors.Is(err, accountdomain.ErrSetupClosed) {
		t.Fatal("setup reopened after admin loss", err)
	}
	// Guard databases with a pre-existing system role even if they lack a marker.
	if _, err := db.Exec(ctx, `DELETE FROM auth.initial_setup`); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckSetupOpen(ctx); !errors.Is(err, accountdomain.ErrSetupClosed) {
		t.Fatal("legacy takeover", err)
	}
	if _, err := r.SaveSetup(ctx, operator, request, payload); !errors.Is(err, accountdomain.ErrSetupClosed) {
		t.Fatal("legacy save", err)
	}
}
