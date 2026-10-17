package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type retentionPageFixture struct {
	user string
	db   *pgxpool.Pool
	cfg  accountservice.RetentionConfig
}

func newRetentionPageFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, batch int) retentionPageFixture {
	t.Helper()
	f := retentionPageFixture{db: db, cfg: retentionPolicy()}
	f.cfg.SessionDays = 1
	f.cfg.BatchSize = batch
	if err := db.QueryRow(ctx, `INSERT INTO auth.users DEFAULT VALUES RETURNING id`).Scan(&f.user); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `UPDATE auth.retention_checkpoints SET cursor_at='-infinity',cursor_id='00000000-0000-0000-0000-000000000000'`)
	t.Cleanup(func() {
		for _, sql := range []string{
			`DELETE FROM auth.refresh_tokens WHERE session_id IN(SELECT id FROM auth.sessions WHERE user_id=$1)`,
			`DELETE FROM auth.refresh_families WHERE session_id IN(SELECT id FROM auth.sessions WHERE user_id=$1)`,
			`DELETE FROM auth.sessions WHERE user_id=$1`, `DELETE FROM auth.users WHERE id=$1`,
		} {
			accessExec(t, db, ctx, sql, f.user)
		}
	})
	return f
}

func (f retentionPageFixture) ledger(t *testing.T, ctx context.Context, ordinal, history int, future bool) string {
	t.Helper()
	profile := "browser"
	if history >= 0 {
		profile = "api"
	}
	var id string
	err := f.db.QueryRow(ctx, `INSERT INTO auth.sessions(credential_profile,token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
		VALUES($1,$2,$3,1,now()-interval '90 days',now()-interval '60 days'+$4*interval '1 second',
		CASE WHEN $5 THEN now()+interval '1 day' ELSE now()-interval '30 days'+$4*interval '1 second' END,
		'password',now()-interval '90 days','','') RETURNING id`, profile, tokengenerate.New().Hash(fmt.Sprintf("retention:%s:%d", f.user, ordinal)), f.user, ordinal, future).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if history >= 0 {
		accessExec(t, f.db, ctx, `INSERT INTO auth.refresh_families(session_id,audience,scope,idle_seconds,generation,created_at,last_rotated_at,absolute_expires_at)
			SELECT id,'orders',ARRAY['orders.read'],3600,GREATEST($2-1,0),created_at,created_at+interval '1 hour',absolute_expires_at FROM auth.sessions WHERE id=$1`, id, history)
		if history > 0 {
			accessExec(t, f.db, ctx, `INSERT INTO auth.refresh_tokens(token_hash,session_id,generation,expires_at,used_at)
			SELECT encode(digest(f.session_id::text||n::text,'sha256'),'hex'),f.session_id,n,f.absolute_expires_at,
			CASE WHEN n<$2-1 THEN f.last_rotated_at END FROM auth.refresh_families f CROSS JOIN generate_series(0,$2-1) n WHERE f.session_id=$1`, id, history)
		}
	}
	return id
}

func (f retentionPageFixture) purge(t *testing.T, parent context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	// New repository each time: progress must survive another worker or process restart.
	if _, err := accountpostgres.New(f.db).PurgeRetention(ctx, f.cfg); err != nil {
		t.Fatal(err)
	}
}

func (f retentionPageFixture) present(t *testing.T, ctx context.Context, id string) bool {
	t.Helper()
	var present bool
	if err := f.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE id=$1)`, id).Scan(&present); err != nil {
		t.Fatal(err)
	}
	return present
}

func checkRetentionPages(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("held page advances to later browser ledger", func(t *testing.T) {
		f := newRetentionPageFixture(t, db, ctx, 1)
		held := f.ledger(t, ctx, 1, 1, true)
		eligible := f.ledger(t, ctx, 2, -1, false)
		f.purge(t, ctx)
		if !f.present(t, ctx, held) || !f.present(t, ctx, eligible) {
			t.Fatal("first page escaped candidate bound")
		}
		f.purge(t, ctx)
		if !f.present(t, ctx, held) || f.present(t, ctx, eligible) {
			t.Fatal("held head starved later ledger")
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id=$1`, held).Scan(&count); err != nil || count != 1 {
			t.Fatal("live reuse window lost", err)
		}
	})
	t.Run("locked ledger skipped and revisited after wrap", func(t *testing.T) {
		f := newRetentionPageFixture(t, db, ctx, 1)
		locked := f.ledger(t, ctx, 1, -1, false)
		later := f.ledger(t, ctx, 2, -1, false)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT id FROM auth.sessions WHERE id=$1 FOR UPDATE`, locked); err != nil {
			t.Fatal(err)
		}
		f.purge(t, ctx)
		f.purge(t, ctx)
		if !f.present(t, ctx, locked) || f.present(t, ctx, later) {
			t.Fatal("row lock blocked progress")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		f.purge(t, ctx)
		f.purge(t, ctx)
		if f.present(t, ctx, locked) {
			t.Fatal("wrapped sweep lost skipped row")
		}
	})
	t.Run("busy checkpoints do not wait or duplicate page", func(t *testing.T) {
		f := newRetentionPageFixture(t, db, ctx, 1)
		id := f.ledger(t, ctx, 1, -1, false)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT kind FROM auth.retention_checkpoints ORDER BY kind FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		f.purge(t, ctx)
		if !f.present(t, ctx, id) {
			t.Fatal("busy checkpoint page executed")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		f.purge(t, ctx)
		if f.present(t, ctx, id) {
			t.Fatal("released checkpoint did not progress")
		}
	})
	t.Run("delete abort rolls back checkpoint", func(t *testing.T) {
		f := newRetentionPageFixture(t, db, ctx, 1)
		id := f.ledger(t, ctx, 1, -1, false)
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_retention_page() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic retention abort'; END $$;
		CREATE TRIGGER reject_retention_page BEFORE DELETE ON auth.sessions FOR EACH ROW EXECUTE FUNCTION auth.reject_retention_page()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_retention_page ON auth.sessions;DROP FUNCTION auth.reject_retention_page()`)
		})
		if _, err := accountpostgres.New(db).PurgeRetention(ctx, f.cfg); err == nil {
			t.Fatal("delete abort ignored")
		}
		var initial bool
		if err := db.QueryRow(ctx, `SELECT cursor_at='-infinity'::timestamptz AND cursor_id='00000000-0000-0000-0000-000000000000' FROM auth.retention_checkpoints WHERE kind='sessions'`).Scan(&initial); err != nil || !initial || !f.present(t, ctx, id) {
			t.Fatal("rollback advanced checkpoint", err)
		}
	})
	t.Run("missing checkpoint fails instead of silent reseed", func(t *testing.T) {
		f := newRetentionPageFixture(t, db, ctx, 1)
		id := f.ledger(t, ctx, 1, -1, false)
		accessExec(t, db, ctx, `DELETE FROM auth.retention_checkpoints WHERE kind='sessions'`)
		t.Cleanup(func() { accessExec(t, db, ctx, `INSERT INTO auth.retention_checkpoints(kind) VALUES('sessions')`) })
		if _, err := accountpostgres.New(db).PurgeRetention(ctx, f.cfg); err == nil || !f.present(t, ctx, id) {
			t.Fatal("missing progress silently ignored", err)
		}
	})
	t.Run("maximum history drains without cascade or held family starvation", func(t *testing.T) {
		f := newRetentionPageFixture(t, db, ctx, 100)
		history := f.ledger(t, ctx, 1, 4096, false)
		empty := f.ledger(t, ctx, 2, 0, false)
		previous := 4096
		for range 46 {
			f.purge(t, ctx)
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id=$1`, history).Scan(&count); err != nil || previous-count > 100 || count > previous {
				t.Fatal("unbounded history drain", previous, count, err)
			}
			if count > 0 && !f.present(t, ctx, history) {
				t.Fatal("ledger cascaded live history")
			}
			previous = count
		}
		if previous != 0 || f.present(t, ctx, history) || f.present(t, ctx, empty) {
			t.Fatal("closed history/family/ledger did not finish draining")
		}
	})
}
