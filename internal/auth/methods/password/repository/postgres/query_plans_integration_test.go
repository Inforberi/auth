package postgres

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Candidate reads mirror the index/range predicates; mutation guarantees have separate SQL tests.
func TestPostgresQueryPlans(t *testing.T) {
	db, ctx := schemaFixtureDSN(t, os.Getenv("AUTH_QUERY_PLAN_DATABASE_URL"), time.Minute)
	migrateFixture(t, db, ctx, "up")
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, sql := range []string{
		`CREATE TEMP TABLE plan_users ON COMMIT DROP AS SELECT gen_random_uuid() AS id,n FROM generate_series(1,100000) n`,
		`INSERT INTO auth.users(id) SELECT id FROM plan_users`,
		`INSERT INTO auth.users(status,created_at,deleted_at) SELECT 'blocked',now()-interval '2 days',now()-interval '1 day' FROM generate_series(1,10000)`,
		`INSERT INTO auth.user_emails(user_id,email) SELECT id,'plan-'||n||'@example.com' FROM plan_users`,
		`INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
		 SELECT encode(digest(id::text,'sha256'),'hex'),id,1,now(),now()+interval '1 day',now()+interval '2 days','','' FROM plan_users`,
		`INSERT INTO auth.password_audit(user_id,event) SELECT id,'password_changed' FROM plan_users`,
		`INSERT INTO auth.email_verifications(digest,email_id,expires_at)
		 SELECT encode(digest(user_id::text,'sha256'),'hex'),id,now()+interval '1 hour' FROM auth.user_emails`,
		`INSERT INTO auth.email_verification_outbox(digest,payload,expires_at,available_at)
		 SELECT digest,decode(repeat('00',32),'hex'),expires_at,now()+interval '30 minutes' FROM auth.email_verifications`,
		`INSERT INTO auth.email_changes(user_id,email_id,old_email,new_email,auth_version,session_hash,confirm_digest,report_digest,completion_payload,expires_at,protect_until)
		 SELECT e.user_id,e.id,e.email,'new-'||e.email::text,1,encode(digest(e.id::text,'sha256'),'hex'),
		 encode(digest(e.id::text||'confirm','sha256'),'hex'),encode(digest(e.id::text||'report','sha256'),'hex'),decode(repeat('00',32),'hex'),
		 now()+interval '1 hour',now()+interval '1 day' FROM auth.user_emails e`,
		`ANALYZE auth.users; ANALYZE auth.sessions; ANALYZE auth.password_audit; ANALYZE auth.email_verifications; ANALYZE auth.email_verification_outbox; ANALYZE auth.email_changes`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	for name, sql := range map[string]string{
		"sessions":            `SELECT id FROM auth.sessions WHERE LEAST(revoked_at,expires_at,absolute_expires_at)<=statement_timestamp()-interval '30 days' ORDER BY LEAST(revoked_at,expires_at,absolute_expires_at),id LIMIT 100 FOR UPDATE SKIP LOCKED`,
		"audit":               `SELECT id FROM auth.password_audit WHERE created_at<=statement_timestamp()-interval '180 days' ORDER BY created_at,id LIMIT 100 FOR UPDATE SKIP LOCKED`,
		"reservations":        `SELECT id FROM auth.users WHERE deleted_at<=statement_timestamp()-interval '30 days' AND NOT email_reuse_blocked AND email_released_at IS NULL ORDER BY deleted_at,id LIMIT 100 FOR UPDATE SKIP LOCKED`,
		"verification expiry": `SELECT digest FROM auth.email_verifications WHERE expires_at<=statement_timestamp() ORDER BY expires_at,digest LIMIT 100 FOR UPDATE SKIP LOCKED`,
		"outbox due":          `SELECT id FROM auth.email_verification_outbox WHERE available_at<=statement_timestamp() AND expires_at>clock_timestamp() AND attempts<5 AND (lease_until IS NULL OR lease_until<=clock_timestamp()) ORDER BY available_at LIMIT 1 FOR UPDATE SKIP LOCKED`,
		"email changes":       `SELECT id FROM auth.email_changes WHERE GREATEST(protect_until,recovery_expires_at)<=statement_timestamp() ORDER BY GREATEST(protect_until,recovery_expires_at),id LIMIT 100 FOR UPDATE SKIP LOCKED`,
	} {
		t.Run(name, func(t *testing.T) {
			var raw []byte
			if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+sql).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var plan []struct {
				Plan struct {
					Hits int     `json:"Shared Hit Blocks"`
					Read int     `json:"Shared Read Blocks"`
					Rows float64 `json:"Actual Rows"`
				}
			}
			if err := json.Unmarshal(raw, &plan); err != nil {
				t.Fatal(err)
			}
			if len(plan) != 1 || plan[0].Plan.Rows != 0 || !strings.Contains(string(raw), "Index Cond") || plan[0].Plan.Hits+plan[0].Plan.Read > 20 {
				t.Fatal("empty range scanned live data", string(raw))
			}
			t.Logf("100000 live rows: %d buffers, 0 due rows", plan[0].Plan.Hits+plan[0].Plan.Read)
		})
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	checkSessionReadLoad(t, db, ctx)
}
