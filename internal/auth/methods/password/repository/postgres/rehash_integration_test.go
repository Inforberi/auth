package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func checkPasswordRehash(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("login upgrades existing password", func(t *testing.T) {
		f := newRegistrationFixture(t, db, ctx)
		legacy := hasher.NewArgon2idHash(1, 16, 1024, 1, 32)
		old, err := legacy.GenerateHash([]byte("Password123"))
		if err != nil {
			t.Fatal(err)
		}
		user, err := f.passwords.CreateUser(ctx, "registration-rehash-login@example.com", old)
		if err != nil {
			t.Fatal(err)
		}
		target := hasher.NewBounded(hasher.NewArgon2idHash(2, 16, 1024, 1, 32), 2)
		svc := passwordservice.New(f.passwords, f.sessions, target, loginTestLimit{})
		result, err := svc.Login(ctx, passwordservice.LoginInput{Email: "registration-rehash-login@example.com", Password: "Password123"})
		if err != nil || result == nil || result.UserID != user {
			t.Fatal("legacy login failed", err)
		}
		credential, err := f.passwords.FindByEmail(ctx, "registration-rehash-login@example.com")
		if err != nil || credential.PasswordHash == old || target.NeedsRehash(credential.PasswordHash) || credential.AuthVersion != 1 {
			t.Fatal("login did not upgrade safely", err)
		}
	})
	t.Run("reset wins without resurrection", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "rehash-reset")
		proof := domain.ResetChallenge{Digest: temporaryTokenDigest("rehash-reset"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.passwords.IssueReset(ctx, f.email, proof); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			err := f.passwords.RehashPassword(ctx, f.user, 1, "old-hash", "rehash")
			if errors.Is(err, domain.ErrInvalidEmailOrPassword) {
				err = nil
			}
			results <- err
		}()
		go func() { <-start; results <- f.passwords.ConsumeReset(ctx, proof.Digest, "reset-hash") }()
		close(start)
		for i := 0; i < 2; i++ {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		credential, err := f.passwords.FindByEmail(ctx, f.email)
		if err != nil || credential.PasswordHash != "reset-hash" || credential.AuthVersion != 2 {
			t.Fatal("reset overwritten", credential, err)
		}
		var revoked bool
		if err := db.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM auth.sessions WHERE token_hash=$1", f.params.TokenHash).Scan(&revoked); err != nil || !revoked {
			t.Fatal("reset session resurrected", err)
		}
	})
	repo := New(db)
	user, err := repo.CreateUser(ctx, "rehash@example.com", "old")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures <- repo.RehashPassword(ctx, user, 1, "old", fmt.Sprintf("replacement-%d", i))
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	credential, err := repo.FindByEmail(ctx, "rehash@example.com")
	if err != nil || credential.AuthVersion != 1 || credential.PasswordHash == "old" {
		t.Fatal("rehash did not preserve version", credential, err)
	}
	winner := credential.PasswordHash
	if err := repo.RehashPassword(ctx, user, 1, "old", "stale"); err != nil {
		t.Fatal(err)
	}
	credential, err = repo.FindByEmail(ctx, "rehash@example.com")
	if err != nil || credential.PasswordHash != winner {
		t.Fatal("stale CAS overwrote winner", err)
	}
	var audit int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM auth.password_audit WHERE user_id=$1", user).Scan(&audit); err != nil || audit != 0 {
		t.Fatal("rehash emitted password change", audit, err)
	}
	if _, err := db.Exec(ctx, "UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1", user); err != nil {
		t.Fatal(err)
	}
	if err := repo.RehashPassword(ctx, user, 1, winner, "stale-version"); !errors.Is(err, domain.ErrInvalidEmailOrPassword) {
		t.Fatal("stale version accepted", err)
	}
	if _, err := db.Exec(ctx, "UPDATE auth.users SET status='blocked' WHERE id=$1", user); err != nil {
		t.Fatal(err)
	}
	if err := repo.RehashPassword(ctx, user, 2, winner, "blocked"); !errors.Is(err, domain.ErrInvalidEmailOrPassword) {
		t.Fatal("blocked account accepted", err)
	}
}
