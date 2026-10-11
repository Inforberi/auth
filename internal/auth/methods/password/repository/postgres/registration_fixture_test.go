package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type registrationFixture struct {
	passwords *PasswordRepo
	sessions  *sessionservice.SessionService
	service   *passwordservice.PasswordService
}

func newRegistrationFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context) registrationFixture {
	t.Helper()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if _, err := db.Exec(cleanup, `DELETE FROM auth.users WHERE id IN (SELECT user_id FROM auth.user_emails WHERE email LIKE 'registration-%@example.com')`); err != nil {
			t.Error("registration fixture cleanup", err)
		}
	})
	cipher, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	accounts := accountpostgres.New(db)
	verification := accountservice.New(accounts, verificationLimits{}, cipher, &verificationMail{}, accountservice.Config{URL: "https://example.com/verify", TTL: 30 * time.Minute, ResendInterval: time.Minute})
	passwords := NewWithRegistration(db, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
		prepared, err := verification.PrepareVerification(email)
		if err != nil {
			return err
		}
		return accounts.QueueInTransaction(ctx, tx, user, emailID, prepared)
	})
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(db), tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute})
	return registrationFixture{passwords: passwords, sessions: sessions, service: passwordservice.New(passwords, sessions, temporaryFixtureHash{}, loginTestLimit{})}
}

type registrationBarrier struct {
	*PasswordRepo
	ready *sync.WaitGroup
}

func (r registrationBarrier) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	found, err := r.PasswordRepo.ExistsByEmail(ctx, email)
	r.ready.Done()
	r.ready.Wait()
	return found, err
}

type registrationCommitReplyFailure struct {
	*PasswordRepo
	failure error
}

func (r registrationCommitReplyFailure) CreateUser(ctx context.Context, email, hash string) (accountdomain.UserID, error) {
	if _, err := r.PasswordRepo.CreateUser(ctx, email, hash); err != nil {
		return "", err
	}
	// Model a lost reply after a real SQL commit, not a pre-commit rollback.
	return "", r.failure
}

type registrationSessionFailure struct {
	*sessionservice.SessionService
	afterCommit bool
	failure     error
}

func (s registrationSessionFailure) CreateSessionAtVersion(ctx context.Context, user accountdomain.UserID, agent, ip string, version int64) (*sessionservice.CreatedSession, error) {
	if s.afterCommit {
		if _, err := s.SessionService.CreateSessionAtVersion(ctx, user, agent, ip, version); err != nil {
			return nil, err
		}
	}
	return nil, s.failure
}

func assertRegistrationRows(t *testing.T, db *pgxpool.Pool, ctx context.Context, email string, sessions int) {
	t.Helper()
	var user accountdomain.UserID
	if err := db.QueryRow(ctx, `SELECT user_id FROM auth.user_emails WHERE email=$1`, email).Scan(&user); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"users", "user_emails", "password_credentials", "user_profile", "email_verification_audit", "sessions"} {
		column, want := "user_id", 1
		if table == "users" {
			column = "id"
		}
		if table == "sessions" {
			want = sessions
		}
		var count int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM auth."+table+" WHERE "+column+"=$1", user).Scan(&count); err != nil || count != want {
			t.Fatal(table, count, want, err)
		}
	}
	var challenges, jobs int
	err := db.QueryRow(ctx, `SELECT count(v.digest),count(o.id) FROM auth.user_emails e JOIN auth.email_verifications v ON v.email_id=e.id LEFT JOIN auth.email_verification_outbox o ON o.digest=v.digest WHERE e.user_id=$1`, user).Scan(&challenges, &jobs)
	if err != nil || challenges != 1 || jobs != 1 {
		t.Fatal("verification duplicated/lost", challenges, jobs, err)
	}
}
