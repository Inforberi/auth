package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func protectionPair(first, second func() error) (error, error) {
	start := make(chan struct{})
	var firstErr, secondErr error
	var wg sync.WaitGroup
	wg.Go(func() { <-start; firstErr = first() })
	wg.Go(func() { <-start; secondErr = second() })
	close(start)
	wg.Wait()
	return firstErr, secondErr
}

func checkProtectedRecoveryRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for _, status := range []accountdomain.Status{accountdomain.StatusBlocked, accountdomain.StatusActive} {
		t.Run("status-"+string(status), func(t *testing.T) {
			for _, order := range []string{"status-first", "recovery-first", "concurrent"} {
				f := protectedFixture(t, db, ctx, "status-"+string(status)+"-"+order)
				recover := func() error {
					return f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement")
				}
				change := func() error { _, err := f.change(ctx, status, 3); return err }
				var recoveryErr, statusErr error
				switch order {
				case "status-first":
					statusErr, recoveryErr = change(), recover()
				case "recovery-first":
					recoveryErr, statusErr = recover(), change()
				default:
					recoveryErr, statusErr = protectionPair(recover, change)
				}
				var currentStatus, hash, email string
				var version int64
				if err := db.QueryRow(ctx, `SELECT u.status,u.auth_version,p.password_hash,e.email FROM auth.users u
					JOIN auth.password_credentials p ON p.user_id=u.id JOIN auth.user_emails e ON e.id=p.email_id
					WHERE u.id=$1`, f.user).Scan(&currentStatus, &version, &hash, &email); err != nil {
					t.Fatal(err)
				}
				if recoveryErr == nil {
					if !errors.Is(statusErr, accountdomain.ErrAccountConflict) || currentStatus != "active" || version != 4 || hash != "replacement" || email != f.email {
						t.Fatal("unsafe recovery-first outcome", recoveryErr, statusErr)
					}
					if status == accountdomain.StatusBlocked {
						if _, err := f.change(ctx, status, 4); err != nil {
							t.Fatal("explicit version retry failed", err)
						}
						assertInactiveAccount(t, ctx, f.statusFixture)
					}
				} else {
					wantVersion := int64(3)
					if status == accountdomain.StatusActive {
						wantVersion = 4
					}
					if statusErr != nil || !errors.Is(recoveryErr, accountdomain.ErrInvalidAccountRecovery) || currentStatus != string(status) || version != wantVersion || hash != "old-hash" || email != f.newEmail {
						t.Fatal("administrative decision bypassed", recoveryErr, statusErr)
					}
				}
				if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
					t.Fatal("recovery authority revived", err)
				}
			}
		})
	}
	t.Run("stale-credentials", func(t *testing.T) {
		for _, action := range []string{"session-issuance", "password-change", "forgot-attacker-email", "confirm", "report"} {
			f := protectedFixture(t, db, ctx, "stale-"+action)
			recover := func() error {
				return f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement")
			}
			attempt := func() error {
				switch action {
				case "session-issuance":
					return f.sessions.CreateSession(ctx, f.params)
				case "password-change":
					return f.passwords.ChangePassword(ctx, f.user, f.params.TokenHash, "old-hash", "attacker-hash")
				case "forgot-attacker-email":
					return f.passwords.IssueReset(ctx, f.newEmail, passworddomain.ResetChallenge{Digest: tokengenerate.New().Hash("attacker-reset-" + action), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)})
				case "confirm":
					return f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest)
				default:
					return f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest)
				}
			}
			recoveryErr, attemptErr := protectionPair(recover, attempt)
			want := accountdomain.ErrInvalidEmailChange
			if action == "session-issuance" {
				want = sessiondomain.ErrSessionNotFound
			}
			if action == "password-change" {
				want = passworddomain.ErrInvalidEmailOrPassword
			}
			if action == "forgot-attacker-email" {
				want = nil
			}
			if recoveryErr != nil || !errors.Is(attemptErr, want) {
				t.Fatal(action, recoveryErr, attemptErr)
			}
			credential, err := f.passwords.FindByEmail(ctx, f.email)
			if err != nil || credential.PasswordHash != "replacement" || credential.AuthVersion != 4 {
				t.Fatal("compromised credentials survived", err)
			}
			var resets, sessions int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.password_resets WHERE user_id=$1),
				(SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL)`, f.user).Scan(&resets, &sessions); err != nil || resets != 0 || sessions != 0 {
				t.Fatal("stale access survived", resets, sessions, err)
			}
		}
	})
	t.Run("previous-change-protection", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "chain")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		original := f.intent
		if err := f.accounts.ConfirmEmailChange(ctx, original.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		f.params.AuthVersion = 2
		f.params.TokenHash = tokengenerate.New().Hash("chain-session")
		if err := f.sessions.CreateSession(ctx, f.params); err != nil {
			t.Fatal(err)
		}
		var err error
		f.snapshot, err = f.accounts.EmailChangeSnapshot(ctx, f.user)
		if err != nil {
			t.Fatal(err)
		}
		f.newEmail = "chain-second@example.com"
		f.intent.ConfirmDigest = tokengenerate.New().Hash("chain-confirm")
		f.intent.ReportDigest = tokengenerate.New().Hash("chain-report")
		f.intent.RecoveryDigest = tokengenerate.New().Hash("chain-recovery")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ReportEmailChange(ctx, original.ReportDigest); err != nil {
			t.Fatal("earlier protection lost", err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, original.RecoveryDigest, "old-hash", "replacement"); err != nil {
			t.Fatal(err)
		}
		for _, intent := range []accountdomain.EmailChangeIntent{original, f.intent} {
			if err := f.accounts.ReportEmailChange(ctx, intent.ReportDigest); !errors.Is(err, accountdomain.ErrInvalidEmailChange) {
				t.Fatal("previous report reblocked recovery", err)
			}
			if _, err := f.accounts.ProtectedRecoveryHash(ctx, intent.RecoveryDigest); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
				t.Fatal("previous recovery survived", err)
			}
		}
		assertChangeLogin(t, ctx, f, f.email, 5)
	})
	t.Run("duplicate-report", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "duplicate-report")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		first, second := protectionPair(func() error { return f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest) }, func() error { return f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest) })
		oneReport := (first == nil && errors.Is(second, accountdomain.ErrInvalidEmailChange)) || (second == nil && errors.Is(first, accountdomain.ErrInvalidEmailChange))
		if !oneReport {
			t.Fatal("duplicate report", first, second)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND o.kind='recovery'`, f.user).Scan(&count); err != nil || count != 1 {
			t.Fatal("multiple recovery jobs", count, err)
		}
	})
}
