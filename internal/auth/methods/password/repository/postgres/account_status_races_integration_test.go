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
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkStatusRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("login snapshot", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "login-race")
		sessions := sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute})
		hasher := loginTestHasher{afterCompare: func() error {
			if _, err := f.change(ctx, accountdomain.StatusBlocked, 1); err != nil {
				return err
			}
			_, err := f.change(ctx, accountdomain.StatusActive, 2)
			return err
		}}
		input := passwordservice.LoginInput{Email: f.email, Password: "Password12345"}
		result, err := passwordservice.New(f.passwords, sessions, hasher, loginTestLimit{}).Login(ctx, input)
		if result != nil || !errors.Is(err, passworddomain.ErrInvalidEmailOrPassword) {
			t.Fatal("old snapshot authenticated after block-unblock", err)
		}
		result, err = passwordservice.New(f.passwords, sessions, loginTestHasher{}, loginTestLimit{}).Login(ctx, input)
		if err != nil || result == nil || result.Token == "" {
			t.Fatal("fresh login failed", err)
		}
		if _, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(result.Token)); err != nil {
			t.Fatal("fresh session invalid", err)
		}
	})
	for _, operation := range []string{"issuance", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			f := newStatusFixture(t, db, ctx, operation+"-race")
			snapshot, err := f.sessions.FindSession(ctx, f.params.TokenHash)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.ExpiresAt = time.Now().UTC().Add(90 * time.Minute)
			params := f.params
			params.TokenHash = tokengenerate.New().Hash(operation + "-racing-new")
			var operationErr, blockErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				if operation == "issuance" {
					_, operationErr = f.sessions.CreateSession(ctx, params)
				} else {
					_, operationErr = f.sessions.RefreshSession(ctx, f.params.TokenHash, snapshot, snapshot.ExpiresAt)
				}
			})
			wg.Go(func() { _, blockErr = f.change(ctx, accountdomain.StatusBlocked, 1) })
			wg.Wait()
			if blockErr != nil || operationErr != nil && !errors.Is(operationErr, sessiondomain.ErrSessionNotFound) {
				t.Fatal("status race", operationErr, blockErr)
			}
			if _, err := f.change(ctx, accountdomain.StatusActive, 2); err != nil {
				t.Fatal(err)
			}
			for _, hash := range []string{f.params.TokenHash, params.TokenHash} {
				if _, err := f.sessions.FindSession(ctx, hash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
					t.Fatal("race revived a session", err)
				}
			}
		})
	}
	t.Run("conflicting updates", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "conflict-race")
		results := make([]error, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() { _, results[i] = f.change(ctx, accountdomain.StatusBlocked, 1) })
		}
		wg.Wait()
		successes := 0
		for _, err := range results {
			if err == nil {
				successes++
			} else if !errors.Is(err, accountdomain.ErrAccountConflict) {
				t.Fatal(err)
			}
		}
		if successes != 1 {
			t.Fatal("optimistic status conflict bypassed")
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "cancelled")
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := f.change(canceled, accountdomain.StatusBlocked, 1); err == nil {
			t.Fatal("cancelled status write succeeded")
		}
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); err != nil {
			t.Fatal("cancelled transaction revoked access", err)
		}
	})
}
