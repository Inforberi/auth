package postgres

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

type directoryPlan struct {
	NodeType   string          `json:"Node Type"`
	Alias      string          `json:"Alias"`
	IndexName  string          `json:"Index Name"`
	IndexCond  string          `json:"Index Cond"`
	ActualRows float64         `json:"Actual Rows"`
	Plans      []directoryPlan `json:"Plans"`
}

func checkUserDirectoryPlans(t *testing.T, db *pgxpool.Pool, ctx context.Context, trace *directoryTrace, request func(string) *httptest.ResponseRecorder) {
	t.Helper()
	accessExec(t, db, ctx, `WITH inserted AS (
		INSERT INTO auth.users(id,status,created_at)
		SELECT md5('directory-bench-'||n)::uuid,CASE WHEN n%1000=0 THEN 'pending' ELSE 'active' END,
		'2025-01-01T00:00:00Z'::timestamptz-n*interval '1 second' FROM generate_series(1,100000) n RETURNING id
	) INSERT INTO auth.user_emails(user_id,email) SELECT id,'bench-'||id||'@example.com' FROM inserted`)
	if _, err := New(db).CreateUser(ctx, "directory-lookup@example.com", "private-lookup-hash"); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `ANALYZE auth.users; ANALYZE auth.user_emails; ANALYZE auth.user_profile`)
	cursor := ""
	for _, tc := range []struct {
		path, index string
		keyset      bool
	}{
		{"?limit=50", "users_directory_page", false},
		{"?status=pending&limit=50", "users_directory_status_page", false},
		{"?limit=50&before=", "users_directory_page", true},
		{"?email=directory-lookup%40example.com", "users_pkey", false},
	} {
		path := tc.path
		if tc.keyset {
			path += cursor
		}
		before := trace.calls
		response := request(path)
		if response.Code != 200 || trace.calls != before+1 {
			t.Fatal("directory must use one SQL statement", response.Code, trace.calls-before)
		}
		if cursor == "" {
			var page accounthttp.UserPageResponse
			if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || page.NextCursor == "" {
				t.Fatal("large dataset did not produce cursor", err)
			}
			cursor = page.NextCursor
		}
		var encoded []byte
		if err := db.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+trace.sql, trace.args...).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var plans []struct {
			Plan directoryPlan `json:"Plan"`
		}
		if err := json.Unmarshal(encoded, &plans); err != nil || len(plans) != 1 {
			t.Fatal("invalid explain result", err)
		}
		found := false
		var walk func(directoryPlan)
		walk = func(node directoryPlan) {
			if node.Alias == "candidate" {
				if node.IndexName != tc.index || node.ActualRows > 51 || (tc.keyset && !strings.Contains(node.IndexCond, "created_at")) {
					t.Fatalf("unexpected page plan: index=%s rows=%.0f keyset=%t", node.IndexName, node.ActualRows, tc.keyset)
				}
				found = true
			}
			for _, child := range node.Plans {
				walk(child)
			}
		}
		walk(plans[0].Plan)
		if !found {
			t.Fatal("page access path missing from plan")
		}
		if tc.index == "users_pkey" && !strings.Contains(string(encoded), "user_emails_email_key") {
			t.Fatal("exact email lookup missed unique index")
		}
		t.Logf("directory plan: %s, keyset=%t, candidate rows <=51 on 100000 synthetic users", tc.index, tc.keyset)
	}
}
