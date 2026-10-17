package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func refreshTransaction(ctx context.Context, db *pgxpool.Pool, fn func(pgx.Tx) error) error {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := accesspostgres.LockAccessSnapshot(bounded, tx); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(bounded)
}

func refreshFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, admin ...bool) (tokenservice.ExchangeInput, string) {
	t.Helper()
	input := jwtActor(t, db, ctx)
	if len(admin) > 0 && admin[0] {
		accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT role_id,'auth.settings.manage' FROM auth.user_roles WHERE user_id=$1`, input.Actor.UserID)
	}
	tokens := tokengenerate.New()
	input.Actor.TokenHash = tokens.Hash("api-ledger:" + input.SessionID)
	if err := db.QueryRow(ctx, `INSERT INTO auth.sessions(credential_profile,token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
		primary_method,primary_verified_at,password_verified_at,mfa_verified_at,user_agent,ip_address)
		VALUES ('api',$1,$2,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',
		'password',clock_timestamp(),clock_timestamp(),clock_timestamp(),'fixture','192.0.2.1') RETURNING id`, input.Actor.TokenHash, input.Actor.UserID).Scan(&input.SessionID); err != nil {
		t.Fatal(err)
	}
	verifier := tokens.Hash("refresh:" + input.SessionID)
	err := refreshTransaction(ctx, db, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT id FROM auth.users WHERE id=$1 FOR SHARE`, input.Actor.UserID)
		if err != nil {
			return err
		}
		_, err = tokenpostgres.CreateRefreshFamily(ctx, tx, tokenservice.CreateRefreshFamilyParams{
			SessionID: input.SessionID, Audience: input.Audience, Scope: input.Scope, Verifier: verifier, IdleTTL: 2 * time.Hour,
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return input, verifier
}

func rotateFixture(ctx context.Context, db *pgxpool.Pool, current, next string) (tokendomain.RefreshRotation, error) {
	var result tokendomain.RefreshRotation
	err := refreshTransaction(ctx, db, func(tx pgx.Tx) error {
		var err error
		result, err = tokenpostgres.RotateRefreshFamily(ctx, tx, current, next)
		return err
	})
	return result, err
}

func checkRefreshStorage(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("atomic rotate throttle and committed replay", func(t *testing.T) {
		input, current := refreshFixture(t, db, ctx)
		next := tokengenerate.New().Hash("next:" + current)
		var expiry, absolute, primary, mfa time.Time
		if err := db.QueryRow(ctx, `SELECT expires_at,absolute_expires_at,primary_verified_at,mfa_verified_at FROM auth.sessions WHERE id=$1`, input.SessionID).Scan(&expiry, &absolute, &primary, &mfa); err != nil {
			t.Fatal(err)
		}
		rotation, err := rotateFixture(ctx, db, current, next)
		if err != nil || rotation.Reused || rotation.Family.Generation != 1 || rotation.Family.Audience != "orders" || rotation.Family.Scope[0] != "orders.read" || rotation.Family.IdleSeconds != 3600 {
			t.Fatal(rotation, err)
		}
		var history, currentCount int
		if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE used_at IS NULL) FROM auth.refresh_tokens WHERE session_id=$1`, input.SessionID).Scan(&history, &currentCount); err != nil || history != 2 || currentCount != 1 {
			t.Fatal("not one successor", history, currentCount, err)
		}
		if _, err := rotateFixture(ctx, db, next, tokengenerate.New().Hash("too soon")); !errors.Is(err, tokendomain.ErrRefreshEarly) {
			t.Fatal("rotation spam accepted", err)
		}
		var unchanged bool
		if err := db.QueryRow(ctx, `SELECT expires_at=$2 AND absolute_expires_at=$3 AND primary_verified_at=$4 AND mfa_verified_at=$5 FROM auth.sessions WHERE id=$1`, input.SessionID, expiry, absolute, primary, mfa).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("storage unexpectedly renewed session/proofs", err)
		}
		rotation, err = rotateFixture(ctx, db, current, tokengenerate.New().Hash("replay successor"))
		if err != nil || !rotation.Reused {
			t.Fatal("spent credential not detected", err)
		}
		var revoked bool
		if err := db.QueryRow(ctx, `SELECT s.revoked_at IS NOT NULL AND f.revoked_at IS NOT NULL FROM auth.sessions s JOIN auth.refresh_families f ON f.session_id=s.id WHERE s.id=$1`, input.SessionID).Scan(&revoked); err != nil || !revoked {
			t.Fatal("reuse not committed", err)
		}
		if _, err := rotateFixture(ctx, db, next, tokengenerate.New().Hash("after reuse")); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("successor survived family revoke", err)
		}
	})

	t.Run("parallel refresh one successor then revoke", func(t *testing.T) {
		input, current := refreshFixture(t, db, ctx)
		var wg sync.WaitGroup
		results := make(chan tokendomain.RefreshRotation, 2)
		failures := make(chan error, 2)
		for _, label := range []string{"first", "second"} {
			wg.Go(func() {
				result, err := rotateFixture(ctx, db, current, tokengenerate.New().Hash(label+current))
				results <- result
				failures <- err
			})
		}
		wg.Wait()
		close(results)
		close(failures)
		for err := range failures {
			if err != nil {
				t.Fatal(err)
			}
		}
		rotated, reused := 0, 0
		for result := range results {
			if result.Reused {
				reused++
			} else {
				rotated++
			}
		}
		if rotated != 1 || reused != 1 {
			t.Fatal("parallel consume", rotated, reused)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id=$1`, input.SessionID).Scan(&count); err != nil || count != 2 {
			t.Fatal("two successors stored", count, err)
		}
	})

	t.Run("unknown secret and rollback", func(t *testing.T) {
		input, current := refreshFixture(t, db, ctx)
		if _, err := rotateFixture(ctx, db, strings.Repeat("f", 64), strings.Repeat("e", 64)); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal(err)
		}
		next := tokengenerate.New().Hash("rollback:" + current)
		cancelled := errors.New("synthetic signing failure")
		err := refreshTransaction(ctx, db, func(tx pgx.Tx) error {
			if _, err := tokenpostgres.RotateRefreshFamily(ctx, tx, current, next); err != nil {
				return err
			}
			return cancelled
		})
		if !errors.Is(err, cancelled) {
			t.Fatal(err)
		}
		var count int
		var revoked bool
		if err := db.QueryRow(ctx, `SELECT count(*),bool_or(f.revoked_at IS NOT NULL) FROM auth.refresh_tokens t JOIN auth.refresh_families f ON f.session_id=t.session_id WHERE f.session_id=$1`, input.SessionID).Scan(&count, &revoked); err != nil || count != 1 || revoked {
			t.Fatal("unknown/rollback mutated family", count, revoked, err)
		}
		if _, err := rotateFixture(ctx, db, current, next); err != nil {
			t.Fatal("rollback consumed original", err)
		}
	})

	t.Run("browser API isolation and immutable bindings", func(t *testing.T) {
		input, current := refreshFixture(t, db, ctx)
		ledger := sessionpostgres.New(db)
		if _, err := ledger.FindSession(ctx, input.Actor.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("API verifier accepted as cookie", err)
		}
		if _, err := ledger.RotateSession(ctx, input.Actor.UserID, input.Actor.TokenHash, tokengenerate.New().Hash("cookie rotation")); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("cookie rotation changed API session", err)
		}
		if _, err := ledger.RecordActivity(ctx, input.Actor.UserID, input.Actor.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("browser activity renewed API session", err)
		}
		if _, err := ledger.ListOwnSessions(ctx, input.Actor.UserID, input.Actor.TokenHash, "", 10); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("API verifier authorized browser management", err)
		}
		if _, err := tokenpostgres.New(db).Exchange(ctx, input, "strict", nil); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("API session reached cookie exchange", err)
		}
		expectSQLState(t, db, ctx, "P0001", `UPDATE auth.sessions SET credential_profile='browser' WHERE id=$1`, input.SessionID)
		expectSQLState(t, db, ctx, "P0001", `UPDATE auth.refresh_families SET audience='other' WHERE session_id=$1`, input.SessionID)
		expectSQLState(t, db, ctx, "P0001", `UPDATE auth.refresh_families SET scope=ARRAY['other.read'] WHERE session_id=$1`, input.SessionID)
		browser := jwtActor(t, db, ctx)
		err := refreshTransaction(ctx, db, func(tx pgx.Tx) error {
			_, err := tokenpostgres.CreateRefreshFamily(ctx, tx, tokenservice.CreateRefreshFamilyParams{
				SessionID: browser.SessionID, Audience: browser.Audience, Scope: browser.Scope, Verifier: current, IdleTTL: time.Hour,
			})
			return err
		})
		if !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("family bound to browser", err)
		}
	})

	for _, test := range []struct {
		name, query string
		want        error
	}{
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`, tokendomain.ErrInvalidRefresh},
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, tokendomain.ErrInvalidRefresh},
		{"logout", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, tokendomain.ErrInvalidRefresh},
		{"generation ceiling", `UPDATE auth.refresh_families SET generation=4095 WHERE session_id IN (SELECT id FROM auth.sessions WHERE user_id=$1)`, tokendomain.ErrRefreshLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, current := refreshFixture(t, db, ctx)
			accessExec(t, db, ctx, test.query, input.Actor.UserID)
			if _, err := rotateFixture(ctx, db, current, tokengenerate.New().Hash(test.name+current)); !errors.Is(err, test.want) {
				t.Fatal(err)
			}
		})
	}
	checkRefreshRetention(t, db, ctx)
}
