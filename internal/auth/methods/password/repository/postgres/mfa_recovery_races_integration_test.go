package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkMFARecoveryRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context, op *mfapostgres.Repository) {
	for _, name := range []string{"normal-login", "password-reset"} {
		t.Run("concurrent-"+name, func(t *testing.T) {
			f := prepareLostFactor(t, db, ctx, "concurrent-"+name, true)
			if err := op.DecideRecovery(ctx, f.decision); err != nil {
				t.Fatal(err)
			}
			var competing func() error
			if name == "normal-login" {
				competing = func() error {
					_, err := f.login.Complete(ctx, mfaservice.CompleteLoginInput{Token: f.input.Token, Binding: f.input.Binding, Code: f.codes[0], Recovery: true, IP: f.input.IP})
					return err
				}
			} else {
				digest := tokengenerate.New().Hash("reset-" + name)
				if err := f.passwords.IssueReset(ctx, f.email, passworddomain.ResetChallenge{Digest: digest, Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
				competing = func() error { return f.passwords.ConsumeReset(ctx, digest, "reset-hash") }
			}
			var recoveryErr, otherErr error
			var group sync.WaitGroup
			gate := make(chan struct{})
			group.Go(func() { <-gate; _, recoveryErr = f.svc.Complete(ctx, f.input) })
			group.Go(func() { <-gate; otherErr = competing() })
			close(gate)
			group.Wait()
			if (recoveryErr == nil) == (otherErr == nil) {
				t.Fatal("race must have one winner", recoveryErr, otherErr)
			}
			if recoveryErr != nil && !errors.Is(recoveryErr, mfadomain.ErrInvalidCode) {
				t.Fatal(recoveryErr)
			}
			if otherErr != nil && !errors.Is(otherErr, mfadomain.ErrInvalidCode) && !errors.Is(otherErr, passworddomain.ErrInvalidReset) {
				t.Fatal(otherErr)
			}
			var version int64
			if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, f.user).Scan(&version); err != nil {
				t.Fatal(err)
			}
			want := int64(3)
			if otherErr == nil && name == "normal-login" {
				want = 2
			}
			if version != want {
				t.Fatal("race version", version, want)
			}
		})
	}
}
