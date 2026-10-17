package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkRefreshRetention(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("refresh audit failure rolls back consume", func(t *testing.T) {
		input, current := refreshFixture(t, db, ctx)
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_refresh_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic refresh audit failure'; END $$;
			CREATE TRIGGER reject_refresh_audit BEFORE INSERT ON auth.refresh_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_refresh_audit()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_refresh_audit ON auth.refresh_audit; DROP FUNCTION auth.reject_refresh_audit()`)
		})
		if _, err := rotateFixture(ctx, db, current, tokengenerate.New().Hash("audit-failure:"+current)); err == nil {
			t.Fatal("audit failure ignored")
		}
		var count, generation int
		var unspent bool
		if err := db.QueryRow(ctx, `SELECT count(*),bool_and(t.used_at IS NULL),max(f.generation)
			FROM auth.refresh_tokens t JOIN auth.refresh_families f ON f.session_id=t.session_id WHERE f.session_id=$1`, input.SessionID).Scan(&count, &unspent, &generation); err != nil || count != 1 || !unspent || generation != 0 {
			t.Fatal("failed audit consumed credential", count, generation, err)
		}
	})

	t.Run("bounded history cleanup precedes ledger", func(t *testing.T) {
		input, _ := refreshFixture(t, db, ctx)
		var expiredID string
		if err := db.QueryRow(ctx, `INSERT INTO auth.sessions(credential_profile,token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
			primary_method,primary_verified_at,mfa_verified_at,user_agent,ip_address)
			VALUES ('api',$1,$2,1,clock_timestamp()-interval '40 days',clock_timestamp()-interval '39 days',clock_timestamp()-interval '38 days',
			'password',clock_timestamp()-interval '40 days',clock_timestamp()-interval '40 days','','') RETURNING id`, tokengenerate.New().Hash("expired-api:"+input.SessionID), input.Actor.UserID).Scan(&expiredID); err != nil {
			t.Fatal(err)
		}
		// Historical family fixture: three verifiers, an already closed absolute window, no secret material.
		accessExec(t, db, ctx, `INSERT INTO auth.refresh_families(session_id,audience,scope,idle_seconds,generation,created_at,last_rotated_at,absolute_expires_at)
			VALUES ($1,'orders',ARRAY['orders.read'],3600,2,clock_timestamp()-interval '40 days',clock_timestamp()-interval '39 days',clock_timestamp()-interval '38 days')`, expiredID)
		for i, label := range []string{"old-zero", "old-one", "old-two"} {
			accessExec(t, db, ctx, `INSERT INTO auth.refresh_tokens(token_hash,session_id,generation,expires_at,used_at)
				SELECT $1,session_id,$2,absolute_expires_at,CASE WHEN $2<2 THEN last_rotated_at END FROM auth.refresh_families WHERE session_id=$3`, tokengenerate.New().Hash(label+expiredID), i, expiredID)
		}
		cfg := retentionPolicy()
		cfg.BatchSize = 1
		repo := accountpostgres.New(db)
		for expected := 2; expected >= 0; expected-- {
			if _, err := repo.PurgeRetention(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id=$1`, expiredID).Scan(&count); err != nil || count != expected {
				t.Fatal("unbounded verifier purge", count, expected, err)
			}
			var present bool
			if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE id=$1)`, expiredID).Scan(&present); err != nil || !present {
				t.Fatal("ledger bypassed bounded history drain", err)
			}
		}
		var familyPresent bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.refresh_families WHERE session_id=$1)`, expiredID).Scan(&familyPresent); err != nil || familyPresent {
			t.Fatal("empty expired family not removed", err)
		}
		if _, err := repo.PurgeRetention(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		var present bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE id=$1)`, expiredID).Scan(&present); err != nil || present {
			t.Fatal("ledger not purged after family drain", err)
		}
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.refresh_tokens WHERE session_id=$1)`, input.SessionID).Scan(&present); err != nil || !present {
			t.Fatal("live detection window was purged", err)
		}
	})
}
