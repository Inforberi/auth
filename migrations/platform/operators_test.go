package platform_test

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
)

type operatorMail struct{ code string }

func (m *operatorMail) SendContext(_ context.Context, _, _, body string) error {
	_, after, _ := strings.Cut(body, "<strong>")
	m.code, _, _ = strings.Cut(after, "</strong>")
	return nil
}

type operatorLimit struct{}

func (operatorLimit) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}

func operatorMigration(t *testing.T, db *pgxpool.Pool, ctx context.Context, file string) {
	t.Helper()
	source, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "BEGIN;"+string(source)+"COMMIT;"); err != nil {
		t.Fatalf("migration %s: %v", file, err)
	}
}

func TestPlatformOperatorsPostgres(t *testing.T) {
	db, ctx := catalogFixture(t)
	operatorMigration(t, db, ctx, "../000001_init.up.sql")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer stop()
		operatorMigration(t, db, cleanup, "../000001_init.down.sql")
	})
	operatorMigration(t, db, ctx, "000002_operators.up.sql")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer stop()
		operatorMigration(t, db, cleanup, "000002_operators.down.sql")
	})
	var realm domain.RealmID
	if err := db.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm`).Scan(&realm); err != nil {
		t.Fatal(err)
	}
	repo, err := operators.New(db, realm)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := operators.New(db, "1c82c477-3a57-4823-8c49-a476550d8a21")
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(wrong.CheckSetupOpen(ctx), accountdomain.ErrSetupClosed) {
		t.Fatal("wrong realm admitted setup")
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	cipher, err := secretbox.NewScoped(key, "initial-setup:v1")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := secretbox.NewScoped(key, "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	hash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1)
	secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	mail := &operatorMail{}
	setup, err := accountservice.NewSetup(repo, operatorLimit{}, cipher, factor, mail, hash, mfatotp.Authenticator{}, accountservice.SetupConfig{Enabled: true, Secret: secret}, "Platform")
	if err != nil {
		t.Fatal(err)
	}
	started, err := setup.Start(ctx, accountservice.SetupStartInput{OperatorSecret: secret, Email: "owner@example.test", Password: "Validpassword1", IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(started.Secret, now)
	if err != nil {
		t.Fatal(err)
	}
	input := accountservice.SetupCompleteInput{OperatorSecret: secret, Token: started.Token, EmailCode: mail.code, TOTP: code, IP: "192.0.2.1"}
	t.Run("wrong proof counted", func(t *testing.T) {
		wrongInput := input
		wrongInput.EmailCode = "00000000"
		if wrongInput.EmailCode == input.EmailCode {
			wrongInput.EmailCode = "11111111"
		}
		if _, err := setup.Complete(ctx, wrongInput); !errors.Is(err, accountdomain.ErrSetupInvalid) {
			t.Fatalf("wrong proof: %v", err)
		}
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.initial_setup`).Scan(&attempts); err != nil || attempts != 1 {
			t.Fatal("rejected attempt was rolled back", err)
		}
	})
	t.Run("platform failure rolls back Auth", func(t *testing.T) {
		if _, err := db.Exec(ctx, `ALTER TABLE platform.operator_audit ADD CONSTRAINT reject_fixture CHECK (false)`); err != nil {
			t.Fatal(err)
		}
		_, completeErr := setup.Complete(ctx, input)
		if _, err := db.Exec(ctx, `ALTER TABLE platform.operator_audit DROP CONSTRAINT reject_fixture`); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(completeErr, accountdomain.ErrDependencyUnavailable) {
			t.Fatalf("audit failure not sanitized: %v", completeErr)
		}
		var clean bool
		if err := db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.users)
			AND NOT EXISTS(SELECT 1 FROM auth.roles) AND NOT EXISTS(SELECT 1 FROM platform.operator_permissions)
			AND EXISTS(SELECT 1 FROM platform.operator_realm WHERE initialized_at IS NULL)
			AND EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NULL AND attempts=1)`).Scan(&clean); err != nil || !clean {
			t.Fatal("partial operator creation", err)
		}
	})
	t.Run("concurrent first owner", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Go(func() { _, err := setup.Complete(ctx, input); results <- err })
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if !errors.Is(err, accountdomain.ErrSetupClosed) {
				t.Fatalf("concurrent completion: %v", err)
			}
		}
		if success != 1 || !errors.Is(repo.CheckSetupOpen(ctx), accountdomain.ErrSetupClosed) {
			t.Fatal("setup is not one-shot")
		}
	})
	var owner accountdomain.UserID
	var complete bool
	if err := db.QueryRow(ctx, `SELECT first_operator_id::text FROM platform.operator_realm`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.users)=1
		AND (SELECT count(*) FROM platform.operator_permissions)=6
		AND (SELECT count(*) FROM platform.operator_audit)=1
		AND (SELECT count(*) FROM auth.mfa_recovery_codes)=10
		AND NOT EXISTS(SELECT 1 FROM auth.sessions)`).Scan(&complete); err != nil || !complete {
		t.Fatal("incomplete owner or unexpected session", err)
	}
	t.Run("SQL authority", func(t *testing.T) { operatorAuthority(t, db, ctx, repo, wrong, owner) })
}
