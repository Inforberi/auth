package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func waitJWTSQLLock(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND pid<>pg_backend_pid())`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("concurrent operation did not reach SQL lock")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
}

func checkJWTExchangeLocks(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	repo := tokenpostgres.New(db)
	signer, _ := jwtSigningFixture(t)
	sign := func(input tokenservice.ExchangeInput) func(context.Context, tokenservice.SessionProof) (*signing.SignedToken, error) {
		return func(ctx context.Context, proof tokenservice.SessionProof) (*signing.SignedToken, error) {
			mfa := proof.MFAVerifiedAt.Unix()
			return signer.Sign(ctx, authjwt.Claims{
				Subject: string(input.Actor.UserID), SessionID: input.SessionID, Audience: input.Audience,
				AuthVersion: proof.AuthVersion, Scope: "orders.read", Mode: authjwt.Strict, ExpiresAt: proof.Now.Add(time.Minute).Unix(),
				AuthTime: proof.VerifiedAt.Unix(), MFATime: &mfa, Methods: []string{"pwd", "mfa"},
			}, proof.Now)
		}
	}
	for _, test := range []struct {
		name   string
		access bool
		query  string
		want   error
	}{
		{"block before issuance", false, `UPDATE auth.users SET status='blocked' WHERE id=$1`, sessiondomain.ErrSessionNotFound},
		{"logout before issuance", false, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, sessiondomain.ErrSessionNotFound},
		{"scope revoke before issuance", true, `DELETE FROM auth.role_permissions WHERE permission_key='orders.read' AND role_id IN (SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, tokendomain.ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := jwtActor(t, db, ctx)
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if test.access {
				if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, test.query, input.Actor.UserID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				result, err := repo.Exchange(ctx, input, authjwt.Strict, sign(input))
				if result != nil {
					done <- errors.New("token issued behind pending revoke")
					return
				}
				done <- err
			}()
			waitJWTSQLLock(t, db, ctx)
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, test.want) {
				t.Fatal("stale issuance snapshot", err)
			}
		})
	}

	t.Run("issuance snapshot blocks logout not other issuers", func(t *testing.T) {
		input := jwtActor(t, db, ctx)
		entered, release := make(chan struct{}), make(chan struct{})
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		done := make(chan error, 1)
		go func() {
			_, err := repo.Exchange(ctx, input, authjwt.Strict, func(ctx context.Context, proof tokenservice.SessionProof) (*signing.SignedToken, error) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return sign(input)(ctx, proof)
			})
			done <- err
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if _, err := repo.Exchange(ctx, input, authjwt.Strict, sign(input)); err != nil {
			t.Fatal("issuance serialized unrelated reads", err)
		}
		revoked := make(chan error, 1)
		go func() {
			revoked <- sessionpostgres.New(db).RevokeOwnSession(ctx, input.Actor.UserID, input.Actor.TokenHash, input.SessionID)
		}()
		waitJWTSQLLock(t, db, ctx)
		close(release)
		if err := <-done; err != nil {
			t.Fatal("issuance did not commit", err)
		}
		if err := <-revoked; err != nil {
			t.Fatal("logout did not commit", err)
		}
		if result, err := repo.Exchange(ctx, input, authjwt.Strict, sign(input)); result != nil || !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("revoked session issued again", err)
		}
	})

	t.Run("cancellation after signing returns nothing", func(t *testing.T) {
		input := jwtActor(t, db, ctx)
		canceled, cancel := context.WithCancel(ctx)
		defer cancel()
		result, err := repo.Exchange(canceled, input, authjwt.Strict, func(ctx context.Context, proof tokenservice.SessionProof) (*signing.SignedToken, error) {
			result, err := sign(input)(ctx, proof)
			cancel()
			return result, err
		})
		if result != nil || err == nil {
			t.Fatal("canceled issuance returned token")
		}
		if _, err := repo.Exchange(ctx, input, authjwt.Strict, sign(input)); err != nil {
			t.Fatal("cancellation leaked locks", err)
		}
	})
}
