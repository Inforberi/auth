package postgres

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
)

type retentionStatement struct {
	sql  string
	args []any
}

type retentionTrace struct{ statements []retentionStatement }

func (r *retentionTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "DELETE FROM auth.sessions") || strings.Contains(data.SQL, "DELETE FROM auth.refresh_families") || strings.Contains(data.SQL, "DELETE FROM auth.refresh_tokens") {
		r.statements = append(r.statements, retentionStatement{sql: data.SQL, args: append([]any(nil), data.Args...)})
	}
	return ctx
}

func (*retentionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

type retentionPlanNode struct {
	Relation string              `json:"Relation Name"`
	Rows     float64             `json:"Actual Rows"`
	Loops    float64             `json:"Actual Loops"`
	Filtered float64             `json:"Rows Removed by Filter"`
	Hits     int                 `json:"Shared Hit Blocks"`
	Reads    int                 `json:"Shared Read Blocks"`
	Plans    []retentionPlanNode `json:"Plans"`
}

func (p retentionPlanNode) visits(relation string) float64 {
	var total float64
	if p.Relation == relation {
		total = (p.Rows + p.Filtered) * p.Loops
	}
	for _, child := range p.Plans {
		total += child.visits(relation)
	}
	return total
}

func TestPostgresRefreshRetentionPlans(t *testing.T) {
	db, ctx := schemaFixtureDSN(t, os.Getenv("AUTH_QUERY_PLAN_DATABASE_URL"), 2*time.Minute)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	trace := &retentionTrace{}
	config := db.Config()
	config.MaxConns = 1
	config.ConnConfig.Tracer = trace
	captured, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(captured.Close)
	cfg := retentionPolicy()
	cfg.SessionDays = 1
	cfg.BatchSize = 100
	if _, err := accountpostgres.New(captured).PurgeRetention(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if len(trace.statements) != 3 {
		t.Fatal("actual retention SQL not captured", len(trace.statements))
	}
	var user string
	if err := db.QueryRow(ctx, `INSERT INTO auth.users DEFAULT VALUES RETURNING id`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	fixture, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Release()
	for _, sql := range []string{
		`CREATE TEMP TABLE retention_sessions AS SELECT gen_random_uuid() id,n FROM generate_series(1,100000) n`,
		`INSERT INTO auth.sessions(id,credential_profile,token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address,primary_method,primary_verified_at)
		 SELECT id,'api',encode(digest(id::text,'sha256'),'hex'),$1,1,now()-interval '70 days',now()-interval '60 days',
		 CASE WHEN n<=90000 THEN now()-interval '40 days' ELSE now()+interval '1 day' END,'','','password',now()-interval '70 days' FROM retention_sessions`,
		`INSERT INTO auth.refresh_families(session_id,audience,scope,idle_seconds,created_at,last_rotated_at,absolute_expires_at)
		 SELECT s.id,'orders',ARRAY['orders.read'],3600,s.created_at,s.created_at,s.absolute_expires_at FROM auth.sessions s`,
		`INSERT INTO auth.refresh_tokens(token_hash,session_id,generation,expires_at)
		 SELECT encode(digest(session_id::text,'sha256'),'hex'),session_id,0,absolute_expires_at FROM auth.refresh_families`,
		`INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
		 VALUES(encode(digest('eligible-browser','sha256'),'hex'),$1,1,now()-interval '50 days',now()-interval '30 days',now()-interval '20 days','','')`,
	} {
		var args []any
		if strings.Contains(sql, "$1") {
			args = []any{user}
		}
		if _, err := fixture.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `ANALYZE auth.sessions;ANALYZE auth.refresh_families;ANALYZE auth.refresh_tokens`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range trace.statements {
		for _, offset := range []int{0, 50000, -1} {
			if strings.Contains(statement.sql, "DELETE FROM auth.refresh_tokens") && offset != 0 {
				continue
			}
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if offset > 0 {
				query := `UPDATE auth.retention_checkpoints SET(cursor_at,cursor_id)=(SELECT LEAST(revoked_at,expires_at,absolute_expires_at),id FROM auth.sessions ORDER BY LEAST(revoked_at,expires_at,absolute_expires_at),id OFFSET $1 LIMIT 1) WHERE kind='sessions'`
				if strings.Contains(statement.sql, "DELETE FROM auth.refresh_families") {
					query = `UPDATE auth.retention_checkpoints SET(cursor_at,cursor_id)=(SELECT absolute_expires_at,session_id FROM auth.refresh_families ORDER BY absolute_expires_at,session_id OFFSET $1 LIMIT 1) WHERE kind='refresh_families'`
				}
				if _, err := tx.Exec(ctx, query, offset); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
			}
			if offset < 0 {
				if _, err := tx.Exec(ctx, `WITH first_page AS(SELECT session_id FROM auth.refresh_families ORDER BY absolute_expires_at,session_id LIMIT 100)
				DELETE FROM auth.refresh_tokens WHERE session_id IN(SELECT session_id FROM first_page)`); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				if strings.Contains(statement.sql, "DELETE FROM auth.sessions") {
					if _, err := tx.Exec(ctx, `WITH first_page AS(SELECT session_id FROM auth.refresh_families ORDER BY absolute_expires_at,session_id LIMIT 100)
					DELETE FROM auth.refresh_families WHERE session_id IN(SELECT session_id FROM first_page)`); err != nil {
						_ = tx.Rollback(ctx)
						t.Fatal(err)
					}
				}
			}
			var raw []byte
			err = tx.QueryRow(ctx, "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) "+statement.sql, statement.args...).Scan(&raw)
			_ = tx.Rollback(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var result []struct {
				Plan retentionPlanNode `json:"Plan"`
			}
			if err := json.Unmarshal(raw, &result); err != nil || len(result) != 1 {
				t.Fatal(err)
			}
			p := result[0].Plan
			for _, relation := range []string{"sessions", "refresh_families", "refresh_tokens"} {
				if p.visits(relation) > float64(cfg.BatchSize*4+10) {
					t.Fatal("actual cleanup scanned past its page", relation, p.visits(relation), string(raw))
				}
			}
			if !strings.Contains(string(raw), "Index Cond") || p.Hits+p.Reads > cfg.BatchSize*30 {
				t.Fatal("cleanup page lost indexed range", string(raw))
			}
			t.Logf("100000 held rows, offset%d: sessions=%.0f families=%.0f tokens=%.0f visits, buffers=%d", offset, p.visits("sessions"), p.visits("refresh_families"), p.visits("refresh_tokens"), p.Hits+p.Reads)
		}
	}
}
