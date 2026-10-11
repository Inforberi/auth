package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func checkTemporaryConcurrency(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("one-secret-per-command", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "concurrent-issue")
		var wg sync.WaitGroup
		results := make(chan *passwordservice.TemporaryIssueResult, 16)
		errs := make(chan error, 16)
		for range 16 {
			wg.Go(func() {
				result, err := f.service.Provision(ctx, f.input)
				results <- result
				errs <- err
			})
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var issued *passwordservice.TemporaryIssueResult
		secrets := 0
		for result := range results {
			if !result.Reused {
				issued = result
			}
			if result.Password != "" {
				secrets++
			}
		}
		if issued == nil || secrets != 1 {
			t.Fatal("command exposed multiple secrets", secrets)
		}
		f.login(t, ctx, issued.Password)
	})
	t.Run("one-current-setup-authority", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "concurrent-login")
		created := f.create(t, ctx)
		var wg sync.WaitGroup
		results := make(chan *passwordservice.TemporaryLoginResult, 16)
		errs := make(chan error, 16)
		for range 16 {
			wg.Go(func() {
				result, err := f.service.Login(ctx, f.input.Email, created.Password, "ip")
				results <- result
				errs <- err
			})
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		valid := 0
		for result := range results {
			_, err := f.repo.CheckTemporarySetup(ctx, temporaryTokenDigest(result.Token))
			if err == nil {
				valid++
			} else if !errors.Is(err, passworddomain.ErrInvalidTemporaryPassword) {
				t.Fatal(err)
			}
		}
		if valid != 1 {
			t.Fatal("parallel login created multiple valid authorities", valid)
		}
	})
	t.Run("reissue-command-exposes-one-secret", func(t *testing.T) {
		f := newTemporaryFixture(t, db, ctx, "concurrent-reissue")
		created := f.create(t, ctx)
		allowTemporaryReissue(t, db, ctx, created.UserID)
		input := passwordservice.TemporaryReissueInput{ActorID: f.input.ActorID, UserID: created.UserID, IdempotencyKey: temporaryRequestKey(t, db, ctx)}
		var wg sync.WaitGroup
		results := make(chan *passwordservice.TemporaryIssueResult, 16)
		errs := make(chan error, 16)
		for range 16 {
			wg.Go(func() {
				result, err := f.service.Reissue(ctx, input)
				results <- result
				errs <- err
			})
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		secrets := 0
		for result := range results {
			if result.Password != "" {
				secrets++
			}
		}
		if secrets != 1 {
			t.Fatal("reissue exposed multiple secrets", secrets)
		}
	})
}
