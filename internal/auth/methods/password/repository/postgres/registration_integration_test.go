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

func checkConcurrentRegistration(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo *PasswordRepo) {
	t.Helper()
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := repo.CreateUser(ctx, "race@example.com", "hash")
			results <- err
		}()
	}
	close(start)
	success, duplicate := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, passworddomain.ErrEmailAlreadyExists):
			duplicate++
		default:
			t.Fatalf("unexpected concurrent registration result: %v", err)
		}
	}
	if success != 1 || duplicate != 1 {
		t.Fatal("registration is not uniquely owned")
	}
	var orphans int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users u LEFT JOIN auth.password_credentials p ON p.user_id=u.id WHERE p.user_id IS NULL`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatal("duplicate registration left orphan user")
	}
}

func checkRegistrationServiceRace(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	f := newRegistrationFixture(t, db, ctx)
	const attempts = 16
	var ready sync.WaitGroup
	ready.Add(attempts)
	repo := registrationBarrier{f.passwords, &ready}
	svc := passwordservice.New(repo, f.sessions, temporaryFixtureHash{}, loginTestLimit{})
	results := make(chan error, attempts)
	for i := range attempts {
		go func() {
			email := "registration-race@example.com"
			if i%2 == 0 {
				email = " Registration-Race@Example.com "
			}
			result, err := svc.Register(ctx, email, "ExamplePass1", "test", "127.0.0.1")
			if err == nil && (result == nil || result.Token == "") {
				err = errors.New("registration returned no session")
			}
			results <- err
		}()
	}
	success, duplicate := 0, 0
	for range attempts {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, passworddomain.ErrEmailAlreadyExists):
			duplicate++
		default:
			t.Fatal("registration race failed", err)
		}
	}
	if success != 1 || duplicate != attempts-1 {
		t.Fatal(success, duplicate)
	}
	assertRegistrationRows(t, db, ctx, "registration-race@example.com", 1)
	var orphans int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users u LEFT JOIN auth.password_credentials p ON p.user_id=u.id WHERE p.user_id IS NULL`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatal("race left orphan users", err)
	}
}
